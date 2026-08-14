//! CLI-seam tests for CA credential handling (ARCHITECTURE.md §2.7).
//!
//! These drive the built binary rather than parsing arguments in-process,
//! because the behavior at issue is what the operator actually sees: which
//! error text comes back, and whether the command reached the network at all.
//! A clap-level test cannot observe either.
//!
//! Every invocation runs with a scratch `HOME` and an explicitly cleared
//! environment. The clearing is not hygiene, it is the point: the CLI loads
//! `.env` from its working directory, so a test that inherited this repo's own
//! `.env` would silently exercise real credentials against the real CA.

use std::path::{Path, PathBuf};
use std::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_ssl-toolbox");

fn scratch_home(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("ssl-toolbox-cli-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("create scratch home");
    path
}

/// Run `ssl-toolbox ca …` with a controlled environment, returning stdout+stderr.
fn run_ca(home: &Path, args: &[&str], env: &[(&str, &str)]) -> String {
    let mut command = Command::new(BINARY);
    command
        .arg("ca")
        .args(args)
        // An empty working directory keeps `dotenvy` from finding any `.env`.
        .current_dir(home)
        .env_clear()
        .env("HOME", home)
        .env("PATH", std::env::var("PATH").unwrap_or_default());
    for (key, value) in env {
        command.env(key, value);
    }

    let output = command.output().expect("the ssl-toolbox binary should run");
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn a_half_configured_environment_override_names_the_missing_variable() {
    // Exporting only SCM_CLIENT_ID is a typo or a half-finished CI change. The
    // operator needs to be told which variable is missing; "no credentials
    // configured" sends them to `ca login` to store credentials they already
    // have, and a fallthrough to the vault would authenticate as another account.
    let home = scratch_home("half-env");

    let output = run_ca(
        &home,
        &["list-profiles"],
        &[("SCM_CLIENT_ID", "only-the-id")],
    );

    assert!(
        output.contains("SCM_CLIENT_SECRET"),
        "the error must name the missing variable, got: {output}"
    );
    // The catch-all "no credentials configured" message also happens to contain
    // that variable name, so without this the assertion above passes for the
    // wrong reason. This is the half-override case specifically.
    assert!(
        !output.contains("No CA credentials configured"),
        "a half-set override is a misconfiguration, not an absence of configuration: {output}"
    );

    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn a_half_configured_environment_override_is_reported_by_the_settings_command() {
    // `ca settings` is the command an operator runs to answer "why is this not
    // working". Reporting "none configured" while SCM_CLIENT_ID is plainly
    // exported makes it the least useful place to look.
    let home = scratch_home("half-env-settings");

    let output = run_ca(&home, &["settings"], &[("SCM_CLIENT_ID", "only-the-id")]);

    assert!(
        output.contains("SCM_CLIENT_SECRET"),
        "settings must surface the half-set override, got: {output}"
    );

    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn with_nothing_configured_the_cli_points_at_login_rather_than_the_network() {
    let home = scratch_home("unconfigured");

    let output = run_ca(&home, &["list-profiles"], &[]);

    assert!(
        output.contains("ca login"),
        "the error should point at the command that fixes it, got: {output}"
    );
    assert!(
        !output.contains("HTTP status"),
        "no CA request should be attempted without credentials, got: {output}"
    );

    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn a_mistyped_collect_format_is_reported_as_a_format_problem() {
    // A typo in --format must not surface as "no credentials configured". The
    // ops executor already validates the format before touching CA config, but
    // the CLI's own credential pre-flight runs first and can mask it — sending
    // the operator to fix an unrelated thing.
    let home = scratch_home("bad-format");

    let output = run_ca(
        &home,
        &[
            "collect", "--id", "1", "--out", "cert.pem", "--format", "bogus",
        ],
        &[],
    );

    assert!(
        output.contains("bogus"),
        "the error must name the rejected format, got: {output}"
    );
    assert!(
        !output.contains("credentials"),
        "a format typo is not a credentials problem, got: {output}"
    );

    let _ = std::fs::remove_dir_all(home);
}

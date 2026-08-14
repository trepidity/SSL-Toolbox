//! Where CA client credentials come from, and how they get there.
//!
//! Before this module existed, `SCM_CLIENT_ID` / `SCM_CLIENT_SECRET` had to be
//! in the process environment, which in practice meant a `.env` file next to a
//! terminal-run CLI. That worked for a shell and not at all for the desktop app:
//! an app launched from Finder or the Start menu inherits no shell environment,
//! so the CA screens could never authenticate.
//!
//! ## Resolution order
//!
//! ```text
//! 1. Environment  SCM_CLIENT_ID + SCM_CLIENT_SECRET   (wins when present)
//! 2. Vault        ~/.ssl-toolbox/credentials.vault    (needs unlocking)
//! ```
//!
//! Environment stays on top deliberately. CI jobs, containers, and jump hosts
//! already export these variables and must keep working untouched; the vault is
//! the answer for an interactive desktop, not a replacement for automation
//! (ARCHITECTURE.md §3).
//!
//! ## Why a passphrase
//!
//! The vault is encrypted (`ssl_toolbox_core::vault`), which means something has
//! to hold the key. On a single-user desktop with no OS keystore in play, the
//! only custodian that is not itself a secret-on-disk is the user. A key derived
//! from machine or user identifiers would be recoverable by anyone holding the
//! file and this source code — obfuscation described as encryption, which is
//! worse than plaintext because it invites misplaced trust.
//!
//! So: unlock once, cache for the life of the process, never write the
//! plaintext anywhere. A CLI invocation unlocks for that one command; the
//! desktop app unlocks once per launch.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use ssl_toolbox_core::vault::{self, SealedBlob, VaultError};
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroize;

use crate::secret::Secret;
use crate::settings;

/// Client credentials for the CA's OAuth 2.0 client-credentials grant.
#[derive(Clone)]
pub struct CaCredentials {
    pub client_id: String,
    pub client_secret: Secret,
}

/// Which layer answered a credential lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CredentialSource {
    /// `SCM_CLIENT_ID` / `SCM_CLIENT_SECRET` were set in the environment.
    Environment,
    /// Read from the unlocked vault.
    Vault,
}

/// What a front-end may know about the stored credentials.
///
/// Note what is absent: the client ID itself. ARCHITECTURE.md §11.3 rule 1 puts
/// `SCM_CLIENT_ID` on the never-printed list alongside the secret, and §9.1
/// already established the length as the one detail safe to surface. So the UI
/// can say "a credential is configured, 32 characters, held in the vault" and
/// cannot say which account it belongs to.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    /// True when `SCM_CLIENT_ID` and `SCM_CLIENT_SECRET` are both set.
    pub environment_override: bool,
    /// True when a vault file exists on disk.
    pub vault_present: bool,
    /// True when the vault has been unlocked in this process.
    pub unlocked: bool,
    /// Where a CA call would get its credentials right now, if anywhere.
    pub active_source: Option<CredentialSource>,
    /// Length of the resolved client ID; never the value itself.
    pub client_id_length: Option<usize>,
    /// Absolute path of the vault file, for the UI to show.
    pub vault_path: Option<String>,
    /// Why the current configuration cannot be used, when it cannot.
    ///
    /// Distinct from "nothing configured": a half-set environment override is a
    /// mistake to correct, not a setup step to perform, and telling the operator
    /// to go store credentials they already have wastes their time.
    pub problem: Option<String>,
}

/// The vault payload, as it exists only between sealing and opening.
#[derive(Serialize, Deserialize)]
struct VaultPayload {
    client_id: String,
    client_secret: String,
}

/// Credentials unlocked in this process.
///
/// Process-global because unlocking is a session act, not a per-operation one —
/// requiring the passphrase on every CA call would push front-ends toward
/// caching it themselves, in a webview heap, which is exactly the place it
/// should not live.
fn unlocked_cache() -> &'static Mutex<Option<CaCredentials>> {
    static CACHE: OnceLock<Mutex<Option<CaCredentials>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

fn environment_credentials() -> Result<Option<CaCredentials>> {
    let id = std::env::var("SCM_CLIENT_ID")
        .ok()
        .filter(|v| !v.is_empty());
    let secret = std::env::var("SCM_CLIENT_SECRET")
        .ok()
        .filter(|v| !v.is_empty());

    match (id, secret) {
        (Some(client_id), Some(client_secret)) => Ok(Some(CaCredentials {
            client_id,
            client_secret: Secret::new(client_secret),
        })),
        // Half an override is a misconfiguration, not a reason to quietly fall
        // through to the vault and authenticate as somebody else.
        (Some(_), None) => Err(anyhow!(
            "SCM_CLIENT_ID is set but SCM_CLIENT_SECRET is not. Set both, or unset both to use the credential vault."
        )),
        (None, Some(_)) => Err(anyhow!(
            "SCM_CLIENT_SECRET is set but SCM_CLIENT_ID is not. Set both, or unset both to use the credential vault."
        )),
        (None, None) => Ok(None),
    }
}

/// What a CA call would find if it asked for credentials right now.
///
/// Every consumer derives its answer from this — the resolver behind a CA call,
/// the status a settings screen renders, and the CLI's decision about whether to
/// prompt for a passphrase. An earlier version had each of those reading the
/// underlying state for itself, and they disagreed: a half-set environment
/// override surfaced as "no credentials configured" through one path and as the
/// correct "SCM_CLIENT_SECRET is not set" through another. Four states, decided
/// once.
pub enum Availability {
    /// Credentials are in hand.
    Ready(CaCredentials, CredentialSource),
    /// A vault exists but has not been unlocked in this process.
    Locked,
    /// Nothing is configured anywhere.
    Missing,
    /// Configured in a way that cannot be used, with the reason.
    Misconfigured(String),
}

/// Decide where credentials would come from, without failing.
pub fn availability() -> Availability {
    match environment_credentials() {
        Ok(Some(from_env)) => {
            return Availability::Ready(from_env, CredentialSource::Environment);
        }
        Err(reason) => return Availability::Misconfigured(reason.to_string()),
        Ok(None) => {}
    }

    if let Some(cached) = unlocked_cache()
        .lock()
        .expect("credential cache poisoned")
        .clone()
    {
        return Availability::Ready(cached, CredentialSource::Vault);
    }

    if vault_exists() {
        Availability::Locked
    } else {
        Availability::Missing
    }
}

/// Resolve the credentials a CA call should use.
pub fn resolve() -> Result<CaCredentials> {
    match availability() {
        Availability::Ready(credentials, _) => Ok(credentials),
        Availability::Misconfigured(reason) => Err(anyhow!(reason)),
        Availability::Locked => Err(anyhow!(
            "CA credentials are locked. Unlock the credential vault with its passphrase before running a CA operation."
        )),
        Availability::Missing => Err(anyhow!(
            "No CA credentials configured. Save a client ID and secret in Settings, or set SCM_CLIENT_ID and SCM_CLIENT_SECRET."
        )),
    }
}

/// Seal a client ID and secret into the vault, replacing anything already there.
///
/// The credentials are also placed in the unlock cache, so saving them is
/// immediately followed by being able to use them — re-prompting for the
/// passphrase we were just handed would be theatre.
pub fn store(client_id: &str, client_secret: &Secret, passphrase: &Secret) -> Result<()> {
    if client_id.trim().is_empty() {
        return Err(anyhow!("A client ID is required"));
    }
    if client_secret.is_empty() {
        return Err(anyhow!("A client secret is required"));
    }
    if passphrase.is_empty() {
        return Err(anyhow!(
            "A vault passphrase is required to encrypt the credentials"
        ));
    }

    let payload = VaultPayload {
        client_id: client_id.trim().to_string(),
        client_secret: client_secret.expose().to_string(),
    };
    let mut plaintext =
        serde_json::to_vec(&payload).context("Failed to encode credentials for sealing")?;
    let sealed = vault::seal(&plaintext, passphrase.expose());
    // The serialized copy is a second plaintext of the secret. Scrub it whether
    // or not sealing succeeded.
    plaintext.zeroize();
    let sealed = sealed?;

    let path = settings::credentials_vault_path()
        .ok_or_else(|| anyhow!("Could not determine a home directory for the credential vault"))?;
    let contents =
        serde_json::to_vec_pretty(&sealed).context("Failed to encode the credential vault")?;
    settings::write_private_file_at(&path, &contents)
        .with_context(|| format!("Failed to write the credential vault to {}", path.display()))?;

    *unlocked_cache().lock().expect("credential cache poisoned") = Some(CaCredentials {
        client_id: payload.client_id,
        client_secret: client_secret.clone(),
    });

    Ok(())
}

/// Open the vault and hold the credentials for the life of this process.
pub fn unlock(passphrase: &Secret) -> Result<()> {
    let path = settings::credentials_vault_path()
        .ok_or_else(|| anyhow!("Could not determine a home directory for the credential vault"))?;
    let raw = std::fs::read(&path).with_context(|| {
        format!(
            "No credential vault at {}. Save a client ID and secret first.",
            path.display()
        )
    })?;
    let sealed: SealedBlob = serde_json::from_slice(&raw)
        .with_context(|| format!("{} is not a valid credential vault", path.display()))?;

    let mut plaintext = match vault::open(&sealed, passphrase.expose()) {
        Ok(plaintext) => plaintext,
        Err(VaultError::WrongPassphrase) => {
            return Err(anyhow!(VaultError::WrongPassphrase.to_string()));
        }
        Err(other) => return Err(anyhow!(other.to_string())),
    };

    let payload = serde_json::from_slice::<VaultPayload>(&plaintext)
        .context("The credential vault opened but its contents are not readable");
    plaintext.zeroize();
    let payload = payload?;

    *unlocked_cache().lock().expect("credential cache poisoned") = Some(CaCredentials {
        client_id: payload.client_id,
        client_secret: Secret::new(payload.client_secret),
    });

    Ok(())
}

/// Drop the unlocked credentials from memory. The vault file is untouched.
pub fn lock() {
    *unlocked_cache().lock().expect("credential cache poisoned") = None;
}

/// Delete the vault file and forget any unlocked credentials.
///
/// Returns whether a file was actually removed, so a front-end can distinguish
/// "cleared" from "there was nothing to clear".
pub fn clear() -> Result<bool> {
    lock();
    let Some(path) = settings::credentials_vault_path() else {
        return Ok(false);
    };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "Failed to delete the credential vault at {}",
                path.display()
            )
        }),
    }
}

fn vault_exists() -> bool {
    settings::credentials_vault_path().is_some_and(|path| path.exists())
}

/// Describe the credential situation without revealing any of it.
///
/// Reads from [`availability`], so what this reports and what a CA call actually
/// does cannot drift apart.
pub fn status() -> CredentialStatus {
    let available = availability();
    let resolved = match &available {
        Availability::Ready(credentials, source) => Some((credentials, *source)),
        _ => None,
    };
    let problem = match &available {
        Availability::Misconfigured(reason) => Some(reason.clone()),
        _ => None,
    };

    CredentialStatus {
        environment_override: matches!(
            available,
            Availability::Ready(_, CredentialSource::Environment)
        ),
        vault_present: vault_exists(),
        unlocked: unlocked_cache()
            .lock()
            .expect("credential cache poisoned")
            .is_some(),
        active_source: resolved.as_ref().map(|(_, source)| *source),
        problem,
        client_id_length: resolved
            .as_ref()
            .map(|(credentials, _)| credentials.client_id.chars().count()),
        vault_path: settings::credentials_vault_path().map(|p| p.display().to_string()),
    }
}

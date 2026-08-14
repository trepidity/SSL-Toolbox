//! The single headless entry point every front-end drives.
//!
//! One [`OpRequest`] in, one [`OpOutcome`] out. The executor performs the
//! operation, records an audit entry for endpoint verifications, and builds the
//! [`JobRecord`] that feeds workflow memory — but it never prompts and never
//! prints. Results are returned as structured data; turning them into ANSI text
//! or React components is a front-end concern.
//!
//! Adding a capability means adding a variant here, which both the CLI and the
//! GUI then expose. That is what keeps the parity contract in ARCHITECTURE.md
//! §10.6 true by construction rather than by discipline.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use ssl_toolbox_core::{
    CertDetails, CertFormat, ConfigInputs, ConfigSummary, LdapConfigCheckResult, PfxDetails,
    TlsCheckResult,
};

use crate::audit::{self, ValidationAuditEntry};
use crate::credentials;
use crate::endpoint::{self, EndpointProtocol};
use crate::secret::Secret;
use crate::settings;
use crate::workflow::{ActionKind, JobRecord};

/// Where an inspection reads the artifact it is about to parse.
///
/// Certificates and CSRs reach an operator two ways: as a file, and as text in
/// a ticket, an email, or a chat message. Modelling that as an enum rather than
/// an optional second field keeps "both set" and "neither set" unrepresentable.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum InputSource {
    Path {
        path: String,
    },
    /// Pasted PEM, or the bare base64 body without its armour.
    Text {
        text: String,
    },
}

impl InputSource {
    fn read(&self, what: &str) -> Result<Vec<u8>> {
        match self {
            Self::Path { path } => {
                std::fs::read(path).with_context(|| format!("Failed to read {what} {path}"))
            }
            Self::Text { text } => ssl_toolbox_core::convert::pasted_to_bytes(text)
                .with_context(|| format!("Could not read the pasted {what}")),
        }
    }

    /// How this input should be named in a job record or a result panel.
    fn label(&self) -> String {
        match self {
            Self::Path { path } => path.clone(),
            Self::Text { .. } => "(pasted)".to_string(),
        }
    }

    /// The path, when there is one — workflow memory only tracks real files.
    fn path(&self) -> Option<&str> {
        match self {
            Self::Path { path } => Some(path),
            Self::Text { .. } => None,
        }
    }
}

/// Optional LDAP RootDSE probe that runs after an LDAPS handshake succeeds.
#[derive(Debug, Deserialize)]
pub struct LdapConfigTest {
    /// Defaults to the LDAPS port when omitted.
    pub port: Option<u16>,
    /// Anonymous bind when absent.
    pub bind_dn: Option<String>,
    pub bind_password: Option<Secret>,
}

impl LdapConfigTest {
    fn to_bind_config(&self) -> Result<ssl_toolbox_core::ldap::LdapBindConfig> {
        match (&self.bind_dn, &self.bind_password) {
            (Some(dn), Some(password)) if !dn.is_empty() => {
                Ok(ssl_toolbox_core::ldap::LdapBindConfig::Simple {
                    bind_dn: dn.clone(),
                    password: password.expose().to_string(),
                })
            }
            (Some(dn), None) if !dn.is_empty() => Err(anyhow::anyhow!(
                "A bind password is required for authenticated bind as {dn}"
            )),
            _ => Ok(ssl_toolbox_core::ldap::LdapBindConfig::Anonymous),
        }
    }
}

/// Every action the toolbox can perform.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
pub enum OpRequest {
    #[serde(rename_all = "camelCase")]
    CreateKey { out: String, password: Secret },

    #[serde(rename_all = "camelCase")]
    GenerateCsr {
        conf: String,
        key: String,
        csr: String,
        /// Passphrase for an existing key, or for the key about to be created.
        key_password: Secret,
        /// When the key file is absent: create it rather than failing.
        #[serde(default)]
        create_key_if_missing: bool,
    },

    #[serde(rename_all = "camelCase")]
    CreatePfx {
        key: String,
        cert: String,
        chain: Option<String>,
        out: String,
        /// Empty when the private key is not encrypted.
        key_password: Secret,
        pfx_password: Secret,
        #[serde(default)]
        legacy: bool,
    },

    #[serde(rename_all = "camelCase")]
    ConvertPfxToLegacy {
        input: String,
        out: String,
        input_password: Secret,
        output_password: Secret,
    },

    #[serde(rename_all = "camelCase")]
    GenerateConfig {
        inputs: Box<ConfigInputs>,
        out: String,
    },

    #[serde(rename_all = "camelCase")]
    GenerateConfigFromCertOrCsr {
        input: String,
        out: String,
        #[serde(default)]
        is_csr: bool,
    },

    /// Read an existing OpenSSL config for viewing or editing.
    #[serde(rename_all = "camelCase")]
    LoadConfig { path: String },

    /// Write edited config text back to disk, verbatim.
    #[serde(rename_all = "camelCase")]
    SaveConfig { path: String, text: String },

    #[serde(rename_all = "camelCase")]
    InspectCert { input: InputSource },

    #[serde(rename_all = "camelCase")]
    InspectCsr { input: InputSource },

    #[serde(rename_all = "camelCase")]
    InspectPfx { input: String, password: Secret },

    /// HTTPS, LDAPS, SMTP, and SQL Server verification share one variant because the
    /// handshake and reporting are identical; only transport setup differs.
    #[serde(rename_all = "camelCase")]
    VerifyEndpoint {
        protocol: EndpointProtocol,
        host: String,
        /// Omitted means "use the protocol default", which also lets a port
        /// embedded in `host` take effect.
        port: Option<u16>,
        #[serde(default = "default_true")]
        verify: bool,
        #[serde(default)]
        full_scan: bool,
        /// Directory to write the presented chain into, one PEM per cert.
        export_certs_dir: Option<String>,
        /// LDAPS only; ignored for other protocols.
        ldap_config_test: Option<LdapConfigTest>,
    },

    #[serde(rename_all = "camelCase")]
    ConvertFormat {
        input: String,
        output: String,
        format: String,
    },

    #[serde(rename_all = "camelCase")]
    IdentifyFormat { input: String },

    /// List the certificate profiles the configured CA offers.
    #[serde(rename_all = "camelCase")]
    CaListProfiles {
        #[serde(default)]
        debug: bool,
    },

    /// Submit a CSR for signing. Returns the CA's request/order ID.
    #[serde(rename_all = "camelCase")]
    CaSubmitCsr {
        csr: String,
        /// File to write the returned request ID into. Optional — the ID is
        /// remembered in the workspace either way.
        out: Option<String>,
        description: Option<String>,
        product_code: Option<String>,
        term_days: Option<i32>,
        #[serde(default)]
        debug: bool,
    },

    /// Download a signed certificate by its request ID.
    #[serde(rename_all = "camelCase")]
    CaCollectCert {
        request_id: String,
        out: String,
        /// `pem`, `chain`, or `pkcs7`.
        format: String,
        #[serde(default)]
        debug: bool,
    },

    /// Find already-issued certificates at the CA.
    #[serde(rename_all = "camelCase")]
    CaSearchCertificates {
        common_name: Option<String>,
        subject_alternative_name: Option<String>,
        serial_number: Option<String>,
        status: Option<String>,
        profile_id: Option<String>,
        size: Option<u32>,
        position: Option<u32>,
        /// Fill in status and dates per row. Defaults to on; costs one extra
        /// request per result when the CA's list response omits them.
        #[serde(default = "default_true")]
        include_dates: bool,
        #[serde(default)]
        debug: bool,
    },

    /// Full record for one certificate found by a search.
    #[serde(rename_all = "camelCase")]
    CaCertificateDetails {
        certificate_id: String,
        #[serde(default)]
        debug: bool,
    },

    /// List CSRs previously submitted to a CA, newest first.
    CaListRequests,

    /// Read the CA endpoint settings and describe the credential situation.
    ///
    /// Returns no secret and no client ID — see [`crate::credentials::CredentialStatus`].
    CaLoadSettings,

    /// Write the CA endpoint settings to user scope.
    ///
    /// Endpoint settings only. Credentials go through [`OpRequest::CaStoreCredentials`],
    /// which is the boundary that keeps ARCHITECTURE.md §11.3 rule 2 true: no
    /// path exists from this variant to a secret in a `*.json` file.
    #[serde(rename_all = "camelCase")]
    CaSaveSettings {
        api_base: String,
        org_id: String,
        product_code: String,
        token_url: String,
    },

    /// Seal a client ID and secret into the encrypted credential vault.
    #[serde(rename_all = "camelCase")]
    CaStoreCredentials {
        client_id: String,
        client_secret: Secret,
        /// Encrypts the vault. Required — there is no unprotected vault.
        vault_passphrase: Secret,
    },

    /// Open the credential vault for the life of this process.
    #[serde(rename_all = "camelCase")]
    CaUnlockCredentials { vault_passphrase: Secret },

    /// Forget the unlocked credentials. The vault file is left alone.
    CaLockCredentials,

    /// Delete the credential vault.
    CaClearCredentials,

    /// Authenticate against the CA without performing an operation.
    #[serde(rename_all = "camelCase")]
    CaTestConnection {
        #[serde(default)]
        debug: bool,
    },
}

fn default_true() -> bool {
    true
}

/// The structured result of an operation.
#[derive(Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum OpOutcome {
    #[serde(rename_all = "camelCase")]
    KeyCreated { path: String },

    #[serde(rename_all = "camelCase")]
    CsrGenerated {
        csr_path: String,
        /// PEM text returned to the desktop so the generated request can be
        /// copied immediately without reading arbitrary local files.
        csr_pem: String,
        key_path: String,
        /// True when the key did not exist and was created as part of this op.
        key_created: bool,
    },

    #[serde(rename_all = "camelCase")]
    PfxCreated { path: String, legacy: bool },

    #[serde(rename_all = "camelCase")]
    ConfigWritten { path: String },

    #[serde(rename_all = "camelCase")]
    ConfigLoaded {
        path: String,
        text: String,
        summary: ConfigSummary,
    },

    #[serde(rename_all = "camelCase")]
    ConfigSaved {
        path: String,
        /// Where the previous contents were copied, when the file already existed.
        backup: Option<String>,
        summary: ConfigSummary,
    },

    #[serde(rename_all = "camelCase")]
    CertInspected {
        path: String,
        chain: Vec<CertDetails>,
    },

    #[serde(rename_all = "camelCase")]
    CsrInspected {
        path: String,
        common_name: String,
        sans: Vec<String>,
        /// The request re-emitted as PEM, so it can be copied straight out of
        /// the result panel regardless of how it was supplied.
        pem: String,
    },

    #[serde(rename_all = "camelCase")]
    PfxInspected { path: String, details: PfxDetails },

    #[serde(rename_all = "camelCase")]
    EndpointVerified(Box<EndpointVerification>),

    #[serde(rename_all = "camelCase")]
    FormatConverted { output: String, format: String },

    #[serde(rename_all = "camelCase")]
    FormatIdentified {
        path: String,
        format: CertFormat,
        description: String,
    },

    #[serde(rename_all = "camelCase")]
    CaProfilesListed {
        provider: String,
        profiles: Vec<ssl_toolbox_ca::CertProfile>,
    },

    #[serde(rename_all = "camelCase")]
    CaCsrSubmitted {
        request_id: String,
        /// Where the ID was also written, when a file was asked for.
        path: Option<String>,
    },

    #[serde(rename_all = "camelCase")]
    CaCertCollected { path: String, format: String },

    #[serde(rename_all = "camelCase")]
    CaCertificatesFound {
        provider: String,
        certificates: Vec<ssl_toolbox_ca::CertificateSummary>,
        /// Offset of this page, so a front-end can page without re-deriving it.
        position: u32,
        /// True when the page came back full, meaning more may follow. The API
        /// reports no total, so "more" cannot be known, only suspected.
        may_have_more: bool,
    },

    #[serde(rename_all = "camelCase")]
    CaCertificateLoaded {
        provider: String,
        certificate: Box<ssl_toolbox_ca::CertificateDetails>,
    },

    #[serde(rename_all = "camelCase")]
    CaRequestsListed {
        requests: Vec<crate::workflow::CaRequestRecord>,
    },

    #[serde(rename_all = "camelCase")]
    CaSettingsLoaded(Box<CaSettingsView>),

    #[serde(rename_all = "camelCase")]
    CaSettingsSaved {
        path: String,
        /// A project-scope config file that will override what was just saved.
        /// Present means the save is correct but will not take effect here.
        shadowed_by: Option<String>,
    },

    /// Returned by every credential mutation, carrying the state that resulted.
    #[serde(rename_all = "camelCase")]
    CaCredentialsChanged {
        status: crate::credentials::CredentialStatus,
    },

    #[serde(rename_all = "camelCase")]
    CaConnectionVerified {
        provider: String,
        source: crate::credentials::CredentialSource,
    },
}

/// CA configuration as a settings screen needs to see it.
///
/// Endpoint settings are returned in full; credentials are described, never
/// returned. The `Secret` type physically cannot serialize, and the client ID is
/// withheld by policy (ARCHITECTURE.md §11.3 rule 1).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaSettingsView {
    /// Empty when no CA plugin is compiled into this build.
    pub provider: Option<String>,
    pub api_base: String,
    pub org_id: String,
    pub product_code: String,
    pub token_url: String,
    /// Where a save would write.
    pub config_path: Option<String>,
    /// A project-scope file currently overriding user scope, if any.
    pub shadowed_by: Option<String>,
    /// Which endpoint settings are currently being supplied by environment
    /// variables, and would therefore ignore anything saved here.
    pub environment_overrides: Vec<String>,
    pub credentials: crate::credentials::CredentialStatus,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointVerification {
    pub protocol: EndpointProtocol,
    pub host: String,
    pub port: u16,
    pub result: TlsCheckResult,
    pub audit: ValidationAuditEntry,
    /// Present only when an LDAP RootDSE probe was requested and succeeded.
    pub ldap_config: Option<LdapConfigCheckResult>,
    /// Set when the LDAP probe was requested but failed; the TLS result is
    /// still valid and worth showing, so this is reported rather than raised.
    pub ldap_config_error: Option<String>,
    pub exported_certs: Vec<String>,
}

/// An operation's result plus the job record describing it.
///
/// The caller decides whether to persist the job — the CLI does so only for
/// successful interactive actions, and the GUI records every completed run.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpResult {
    pub outcome: OpOutcome,
    pub job: JobRecord,
}

/// Perform one operation.
///
/// Endpoint verification records an audit entry as a side effect (including on
/// handshake failure, which is itself a finding worth keeping) and appends to
/// `~/.ssl-toolbox/validation-log.jsonl`.
pub fn run(request: OpRequest) -> Result<OpResult> {
    match request {
        OpRequest::CreateKey { out, password } => {
            ssl_toolbox_core::key_csr::generate_private_key(&out, password.expose())?;
            Ok(OpResult {
                job: job(ActionKind::CreateKey, format!("Create key {out}"))
                    .output("key", &out)
                    .build(),
                outcome: OpOutcome::KeyCreated { path: out },
            })
        }

        OpRequest::GenerateCsr {
            conf,
            key,
            csr,
            key_password,
            create_key_if_missing,
        } => {
            let key_exists = Path::new(&key).exists();
            if !key_exists && !create_key_if_missing {
                return Err(anyhow::anyhow!(
                    "Private key {key} does not exist. Create it first, or allow key creation."
                ));
            }

            if key_exists {
                ssl_toolbox_core::key_csr::generate_csr(
                    &conf,
                    &key,
                    &csr,
                    key_password.as_option(),
                )?;
            } else {
                if key_password.is_empty() {
                    return Err(anyhow::anyhow!(
                        "A passphrase is required to create a new private key"
                    ));
                }
                ssl_toolbox_core::key_csr::generate_key_and_csr(
                    &conf,
                    &key,
                    &csr,
                    key_password.expose(),
                )?;
            }

            let csr_pem = fs::read_to_string(&csr)
                .with_context(|| format!("Could not read generated CSR {csr}"))?;

            Ok(OpResult {
                job: job(ActionKind::Generate, format!("Generate CSR {csr}"))
                    .input("conf", &conf)
                    .output("key", &key)
                    .output("csr", &csr)
                    .build(),
                outcome: OpOutcome::CsrGenerated {
                    csr_path: csr,
                    csr_pem,
                    key_path: key,
                    key_created: !key_exists,
                },
            })
        }

        OpRequest::CreatePfx {
            key,
            cert,
            chain,
            out,
            key_password,
            pfx_password,
            legacy,
        } => {
            let builder = if legacy {
                ssl_toolbox_core::pfx::create_pfx_legacy
            } else {
                ssl_toolbox_core::pfx::create_pfx
            };
            builder(
                &key,
                &cert,
                chain.as_deref(),
                &out,
                key_password.as_option(),
                pfx_password.expose(),
            )?;

            let kind = if legacy {
                ActionKind::CreateLegacyPfx
            } else {
                ActionKind::CreatePfx
            };
            let mut record = job(kind, format!("Create PFX {out}"))
                .input("key", &key)
                .input("cert", &cert)
                .output(if legacy { "legacy_pfx" } else { "pfx" }, &out);
            if let Some(chain_path) = chain.as_deref() {
                record = record.input("chain", chain_path);
            }

            Ok(OpResult {
                job: record.build(),
                outcome: OpOutcome::PfxCreated { path: out, legacy },
            })
        }

        OpRequest::ConvertPfxToLegacy {
            input,
            out,
            input_password,
            output_password,
        } => {
            let pfx_bytes = std::fs::read(&input)
                .with_context(|| format!("Failed to read input PFX {input}"))?;
            ssl_toolbox_core::pfx::create_pfx_legacy_3des(
                &pfx_bytes,
                input_password.expose(),
                &out,
                output_password.expose(),
            )?;

            Ok(OpResult {
                job: job(ActionKind::CreateLegacyPfx, format!("Legacy PFX {out}"))
                    .input("pfx", &input)
                    .output("legacy_pfx", &out)
                    .build(),
                outcome: OpOutcome::PfxCreated {
                    path: out,
                    legacy: true,
                },
            })
        }

        OpRequest::LoadConfig { path } => {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("Could not read config {path}"))?;
            let summary =
                ssl_toolbox_core::config::summarize_conf(&text, Path::new(&path).parent());
            Ok(OpResult {
                job: job(ActionKind::ViewConfig, format!("View config {path}"))
                    .input("config", &path)
                    .build(),
                outcome: OpOutcome::ConfigLoaded {
                    path,
                    text,
                    summary,
                },
            })
        }

        OpRequest::SaveConfig { path, text } => {
            // Copy the outgoing contents aside *before* writing. Doing it after
            // would produce a backup byte-identical to the new file — a backup
            // that cannot restore anything.
            let backup = if Path::new(&path).exists() {
                let backup_path = format!("{path}.bak");
                std::fs::copy(&path, &backup_path).with_context(|| {
                    format!("Could not back up {path} to {backup_path} — nothing was written")
                })?;
                Some(backup_path)
            } else {
                None
            };

            std::fs::write(&path, &text)
                .with_context(|| format!("Could not write config {path}"))?;
            let summary =
                ssl_toolbox_core::config::summarize_conf(&text, Path::new(&path).parent());
            Ok(OpResult {
                job: job(ActionKind::EditConfig, format!("Edit config {path}"))
                    .output("config", &path)
                    .build(),
                outcome: OpOutcome::ConfigSaved {
                    path,
                    backup,
                    summary,
                },
            })
        }

        OpRequest::GenerateConfig { inputs, out } => {
            ssl_toolbox_core::config::generate_conf_from_inputs(&inputs, &out)?;
            Ok(OpResult {
                job: job(ActionKind::NewConfig, format!("New config {out}"))
                    .output("config", &out)
                    .build(),
                outcome: OpOutcome::ConfigWritten { path: out },
            })
        }

        OpRequest::GenerateConfigFromCertOrCsr { input, out, is_csr } => {
            ssl_toolbox_core::config::generate_conf_from_cert_or_csr(&input, &out, is_csr)?;
            Ok(OpResult {
                job: job(
                    ActionKind::ConfigFromExisting,
                    format!("Config from {input}"),
                )
                .input(if is_csr { "csr" } else { "cert" }, &input)
                .output("config", &out)
                .build(),
                outcome: OpOutcome::ConfigWritten { path: out },
            })
        }

        OpRequest::InspectCert { input } => {
            let content = input.read("certificate")?;
            let chain = ssl_toolbox_core::x509_utils::extract_cert_chain_details(&content)?;
            let label = input.label();
            let mut record = job(ActionKind::ViewCert, format!("View cert {label}"));
            if let Some(path) = input.path() {
                record = record.input("cert", path);
            }
            Ok(OpResult {
                job: record.build(),
                outcome: OpOutcome::CertInspected { path: label, chain },
            })
        }

        OpRequest::InspectCsr { input } => {
            let content = input.read("CSR")?;
            let (common_name, sans) =
                ssl_toolbox_core::key_csr::extract_csr_details_from_bytes(&content)?;
            let pem = ssl_toolbox_core::key_csr::csr_to_pem_text(&content)?;
            let label = input.label();
            let mut record = job(ActionKind::ViewCsr, format!("View CSR {label}"));
            if let Some(path) = input.path() {
                record = record.input("csr", path);
            }
            Ok(OpResult {
                job: record.build(),
                outcome: OpOutcome::CsrInspected {
                    path: label,
                    common_name,
                    sans,
                    pem,
                },
            })
        }

        OpRequest::InspectPfx { input, password } => {
            let pfx_bytes =
                std::fs::read(&input).with_context(|| format!("Failed to read PFX {input}"))?;
            let details =
                ssl_toolbox_core::pfx::extract_pfx_bundle_details(&pfx_bytes, password.expose())?;
            Ok(OpResult {
                job: job(ActionKind::ViewPfx, format!("View PFX {input}"))
                    .input("pfx", &input)
                    .build(),
                outcome: OpOutcome::PfxInspected {
                    path: input,
                    details,
                },
            })
        }

        OpRequest::VerifyEndpoint {
            protocol,
            host,
            port,
            verify,
            full_scan,
            export_certs_dir,
            ldap_config_test,
        } => verify_endpoint(
            protocol,
            &host,
            port,
            verify,
            full_scan,
            export_certs_dir.as_deref(),
            ldap_config_test.as_ref(),
        ),

        OpRequest::ConvertFormat {
            input,
            output,
            format,
        } => {
            let normalized = format.to_lowercase();
            match normalized.as_str() {
                "der" => ssl_toolbox_core::convert::pem_to_der(&input, &output)?,
                "pem" => ssl_toolbox_core::convert::der_to_pem(&input, &output)?,
                "base64" => ssl_toolbox_core::convert::pem_to_base64(&input, &output)?,
                other => {
                    return Err(anyhow::anyhow!(
                        "Unsupported format: '{other}'. Use: pem, der, base64"
                    ));
                }
            }

            Ok(OpResult {
                job: job(ActionKind::Convert, format!("Convert to {normalized}"))
                    .input("input", &input)
                    .replay("format", &normalized)
                    .output("output", &output)
                    .build(),
                outcome: OpOutcome::FormatConverted {
                    output,
                    format: normalized,
                },
            })
        }

        OpRequest::CaListProfiles { debug } => {
            let plugin = ca_plugin(debug)?;
            let profiles = plugin.list_profiles(debug)?;
            Ok(OpResult {
                job: job(
                    ActionKind::CaProfiles,
                    format!("List {} profiles", plugin.name()),
                )
                .build(),
                outcome: OpOutcome::CaProfilesListed {
                    provider: plugin.name().to_string(),
                    profiles,
                },
            })
        }

        OpRequest::CaSubmitCsr {
            csr,
            out,
            description,
            product_code,
            term_days,
            debug,
        } => {
            let plugin = ca_plugin(debug)?;
            let csr_pem = std::fs::read_to_string(&csr)
                .with_context(|| format!("Failed to read CSR {csr}"))?;
            let options = ssl_toolbox_ca::SubmitOptions {
                description: description.clone(),
                product_code: product_code.clone(),
                term_days,
            };
            let request_id = plugin.submit_csr(&csr_pem, &options, debug)?;

            // Writing the ID to a file is optional now that submissions are
            // remembered: the desktop app has nowhere natural to put a file,
            // and losing the ID means hunting through the CA console.
            let written_to = match out.as_deref() {
                Some(path) if !path.is_empty() => {
                    std::fs::write(path, &request_id)
                        .with_context(|| format!("Failed to write request ID to {path}"))?;
                    Some(path.to_string())
                }
                _ => None,
            };

            remember_ca_request(&request_id, &csr, &csr_pem, description, product_code);

            let mut record = job(ActionKind::CaSubmit, format!("Submit CSR {csr}"))
                .input("csr", &csr)
                .replay("ca_request_id", &request_id);
            if let Some(path) = written_to.as_deref() {
                record = record.output("ca_request_id", path);
            }

            Ok(OpResult {
                job: record.build(),
                outcome: OpOutcome::CaCsrSubmitted {
                    request_id,
                    path: written_to,
                },
            })
        }

        OpRequest::CaCollectCert {
            request_id,
            out,
            format,
            debug,
        } => {
            let collect_format =
                ssl_toolbox_ca::CollectFormat::parse(&format).ok_or_else(|| {
                    let supported = ssl_toolbox_ca::CollectFormat::ALL
                        .map(|value| value.token())
                        .join(", ");
                    anyhow::anyhow!(
                        "Unsupported collect format: '{format}'. Use one of: {supported}"
                    )
                })?;
            let normalized = collect_format.token().to_string();

            let plugin = ca_plugin(debug)?;
            let certificate = plugin.collect_cert(&request_id, collect_format, debug)?;
            // Written as bytes: one of the formats is DER, and re-encoding it
            // through a String would corrupt it.
            std::fs::write(&out, &certificate)
                .with_context(|| format!("Failed to write certificate to {out}"))?;

            Ok(OpResult {
                job: job(
                    ActionKind::CaSubmit,
                    format!("Collect certificate {request_id}"),
                )
                .replay("request_id", &request_id)
                .replay("format", &normalized)
                .output(
                    if collect_format == ssl_toolbox_ca::CollectFormat::CertificateChainPem {
                        "chain"
                    } else {
                        "cert"
                    },
                    &out,
                )
                .build(),
                outcome: OpOutcome::CaCertCollected {
                    path: out,
                    format: normalized,
                },
            })
        }

        OpRequest::CaSearchCertificates {
            common_name,
            subject_alternative_name,
            serial_number,
            status,
            profile_id,
            size,
            position,
            include_dates,
            debug,
        } => {
            let filter = ssl_toolbox_ca::CertificateFilter {
                common_name,
                subject_alternative_name,
                serial_number,
                status,
                profile_id,
                size,
                position,
                include_dates,
            };
            let requested = filter.size.unwrap_or(25);
            let offset = filter.position.unwrap_or(0);

            let plugin = ca_plugin(debug)?;
            let certificates = plugin.search_certificates(&filter, debug)?;
            let may_have_more = certificates.len() as u32 >= requested;

            Ok(OpResult {
                job: job(
                    ActionKind::CaSearch,
                    format!("Search {} certificates", plugin.name()),
                )
                .transient()
                .build(),
                outcome: OpOutcome::CaCertificatesFound {
                    provider: plugin.name().to_string(),
                    certificates,
                    position: offset,
                    may_have_more,
                },
            })
        }

        OpRequest::CaCertificateDetails {
            certificate_id,
            debug,
        } => {
            let plugin = ca_plugin(debug)?;
            let certificate = plugin.certificate_details(&certificate_id, debug)?;
            Ok(OpResult {
                job: job(
                    ActionKind::CaSearch,
                    format!("Read certificate {certificate_id}"),
                )
                .transient()
                .build(),
                outcome: OpOutcome::CaCertificateLoaded {
                    provider: plugin.name().to_string(),
                    certificate: Box::new(certificate),
                },
            })
        }

        OpRequest::CaListRequests => {
            let requests = settings::load_state().ca_requests;
            Ok(OpResult {
                job: job(ActionKind::CaSubmit, "List CA submissions")
                    .transient()
                    .build(),
                outcome: OpOutcome::CaRequestsListed { requests },
            })
        }

        OpRequest::CaLoadSettings => {
            let view = ca_settings_view()?;
            Ok(OpResult {
                job: job(ActionKind::CaSettings, "Load CA settings")
                    .transient()
                    .build(),
                outcome: OpOutcome::CaSettingsLoaded(Box::new(view)),
            })
        }

        OpRequest::CaSaveSettings {
            api_base,
            org_id,
            product_code,
            token_url,
        } => {
            let (path, shadowed_by) =
                ca_settings_save(&api_base, &org_id, &product_code, &token_url)?;
            Ok(OpResult {
                job: job(ActionKind::CaSettings, "Save CA settings")
                    .output("ca_settings", &path)
                    .build(),
                outcome: OpOutcome::CaSettingsSaved { path, shadowed_by },
            })
        }

        OpRequest::CaStoreCredentials {
            client_id,
            client_secret,
            vault_passphrase,
        } => {
            credentials::store(&client_id, &client_secret, &vault_passphrase)?;
            Ok(OpResult {
                job: job(ActionKind::CaCredentials, "Store CA credentials").build(),
                outcome: OpOutcome::CaCredentialsChanged {
                    status: credentials::status(),
                },
            })
        }

        OpRequest::CaUnlockCredentials { vault_passphrase } => {
            credentials::unlock(&vault_passphrase)?;
            Ok(OpResult {
                job: job(ActionKind::CaCredentials, "Unlock CA credentials")
                    .transient()
                    .build(),
                outcome: OpOutcome::CaCredentialsChanged {
                    status: credentials::status(),
                },
            })
        }

        OpRequest::CaLockCredentials => {
            credentials::lock();
            Ok(OpResult {
                job: job(ActionKind::CaCredentials, "Lock CA credentials")
                    .transient()
                    .build(),
                outcome: OpOutcome::CaCredentialsChanged {
                    status: credentials::status(),
                },
            })
        }

        OpRequest::CaClearCredentials => {
            let removed = credentials::clear()?;
            Ok(OpResult {
                job: job(
                    ActionKind::CaCredentials,
                    if removed {
                        "Delete CA credential vault"
                    } else {
                        "Delete CA credential vault (nothing stored)"
                    },
                )
                .build(),
                outcome: OpOutcome::CaCredentialsChanged {
                    status: credentials::status(),
                },
            })
        }

        OpRequest::CaTestConnection { debug } => {
            let source = credentials::status()
                .active_source
                .ok_or_else(|| anyhow::anyhow!("No CA credentials are available to test"))?;
            let plugin = ca_plugin(debug)?;
            plugin.test_auth(debug)?;
            Ok(OpResult {
                job: job(
                    ActionKind::CaCredentials,
                    format!("Test {} authentication", plugin.name()),
                )
                .transient()
                .build(),
                outcome: OpOutcome::CaConnectionVerified {
                    provider: plugin.name().to_string(),
                    source,
                },
            })
        }

        OpRequest::IdentifyFormat { input } => {
            let data =
                std::fs::read(&input).with_context(|| format!("Failed to read file {input}"))?;
            let format = ssl_toolbox_core::convert::detect_format(&data);
            Ok(OpResult {
                job: job(ActionKind::Identify, format!("Identify {input}"))
                    .input("input", &input)
                    .build(),
                outcome: OpOutcome::FormatIdentified {
                    path: input,
                    format,
                    description: ssl_toolbox_core::convert::format_description(format).to_string(),
                },
            })
        }
    }
}

/// Construct the compiled-in CA plugin.
///
/// Plugin wiring lives here rather than in a front-end so the CLI and the GUI
/// reach the same CA with the same configuration precedence: endpoint settings
/// from `.ssl-toolbox/<name>.json` overlaid by environment variables, and
/// credentials resolved by [`credentials::resolve`].
#[cfg(feature = "sectigo")]
fn ca_plugin(debug: bool) -> Result<Box<dyn ssl_toolbox_ca::CaPlugin>> {
    let config: ssl_toolbox_ca_sectigo::SectigoConfig = settings::load_ca_config("sectigo");
    let creds = credentials::resolve()?;
    ssl_toolbox_ca_sectigo::SectigoPlugin::configure_with_config(
        &config,
        &creds.client_id,
        creds.client_secret.expose(),
        debug,
    )
}

#[cfg(not(feature = "sectigo"))]
fn ca_plugin(_debug: bool) -> Result<Box<dyn ssl_toolbox_ca::CaPlugin>> {
    Err(anyhow::anyhow!(
        "No CA plugin compiled. Build with --features sectigo"
    ))
}

/// Record a submitted CSR so the collect step can offer the ID back later.
///
/// Failure to persist is swallowed for the same reason job recording is: the
/// certificate order exists at the CA whether or not we managed to write a note
/// about it, and turning a bookkeeping failure into a submission failure would
/// invite the operator to submit a second time.
fn remember_ca_request(
    request_id: &str,
    csr_path: &str,
    csr_pem: &str,
    description: Option<String>,
    product_code: Option<String>,
) {
    let common_name = ssl_toolbox_core::key_csr::extract_csr_details_from_bytes(csr_pem.as_bytes())
        .map(|(cn, _)| cn)
        .unwrap_or_default();

    let mut state = settings::load_state();
    crate::workflow::push_ca_request(
        &mut state.ca_requests,
        crate::workflow::CaRequestRecord {
            request_id: request_id.to_string(),
            common_name,
            description: description.unwrap_or_default(),
            profile: product_code.unwrap_or_default(),
            csr_path: csr_path.to_string(),
            timestamp_secs: now_secs(),
        },
    );
    let _ = settings::save_state(&state);
}

/// Endpoint settings currently coming from the environment rather than a file.
///
/// Surfaced so a settings screen can say "this field is being overridden" instead
/// of letting the user edit a value that a `SECTIGO_*` variable silently wins over.
fn environment_overrides() -> Vec<String> {
    [
        "SECTIGO_API_BASE",
        "SECTIGO_ORG_ID",
        "SECTIGO_PRODUCT_CODE",
        "SCM_TOKEN_URL",
    ]
    .into_iter()
    .filter(|name| std::env::var(name).is_ok_and(|value| !value.is_empty()))
    .map(str::to_string)
    .collect()
}

#[cfg(feature = "sectigo")]
fn ca_settings_view() -> Result<CaSettingsView> {
    let config: ssl_toolbox_ca_sectigo::SectigoConfig = settings::load_ca_config("sectigo");
    Ok(CaSettingsView {
        provider: Some("Sectigo".to_string()),
        api_base: config.api_base,
        org_id: config.org_id,
        product_code: config.product_code,
        token_url: config.token_url,
        config_path: settings::ca_config_path("sectigo").map(|path| path.display().to_string()),
        shadowed_by: settings::ca_config_override_path("sectigo")
            .map(|path| path.display().to_string()),
        environment_overrides: environment_overrides(),
        credentials: credentials::status(),
    })
}

#[cfg(not(feature = "sectigo"))]
fn ca_settings_view() -> Result<CaSettingsView> {
    Ok(CaSettingsView {
        provider: None,
        api_base: String::new(),
        org_id: String::new(),
        product_code: String::new(),
        token_url: String::new(),
        config_path: None,
        shadowed_by: None,
        environment_overrides: environment_overrides(),
        credentials: credentials::status(),
    })
}

#[cfg(feature = "sectigo")]
fn ca_settings_save(
    api_base: &str,
    org_id: &str,
    product_code: &str,
    token_url: &str,
) -> Result<(String, Option<String>)> {
    let config = ssl_toolbox_ca_sectigo::SectigoConfig {
        api_base: api_base.trim().to_string(),
        org_id: org_id.trim().to_string(),
        product_code: product_code.trim().to_string(),
        token_url: token_url.trim().to_string(),
    };
    let path = settings::save_ca_config("sectigo", &config)?;
    let shadowed_by =
        settings::ca_config_override_path("sectigo").map(|path| path.display().to_string());
    Ok((path.display().to_string(), shadowed_by))
}

#[cfg(not(feature = "sectigo"))]
fn ca_settings_save(
    _api_base: &str,
    _org_id: &str,
    _product_code: &str,
    _token_url: &str,
) -> Result<(String, Option<String>)> {
    Err(anyhow::anyhow!(
        "No CA plugin compiled. Build with --features sectigo"
    ))
}

#[allow(clippy::too_many_arguments)]
fn verify_endpoint(
    protocol: EndpointProtocol,
    raw_host: &str,
    port: Option<u16>,
    verify: bool,
    full_scan: bool,
    export_certs_dir: Option<&str>,
    ldap_config_test: Option<&LdapConfigTest>,
) -> Result<OpResult> {
    let default_port = protocol.default_port();
    let (host, port) =
        endpoint::normalize_target(raw_host, port.unwrap_or(default_port), default_port)?;

    // STARTTLS cannot be probed with the direct-handshake cipher scan.
    let full_scan = full_scan && protocol.supports_full_scan();

    let kind = match protocol {
        EndpointProtocol::Https => ActionKind::VerifyHttps,
        EndpointProtocol::Ldaps => ActionKind::VerifyLdaps,
        EndpointProtocol::Smtp => ActionKind::VerifySmtp,
        EndpointProtocol::SqlServer => ActionKind::VerifySqlServer,
    };

    let check = match protocol {
        EndpointProtocol::Smtp => {
            ssl_toolbox_core::smtp::connect_and_check_smtp(&host, port, verify)
        }
        EndpointProtocol::SqlServer => {
            ssl_toolbox_core::mssql::connect_and_check_sql_server(&host, port, verify)
        }
        _ => ssl_toolbox_core::tls::connect_and_check(&host, port, verify, full_scan),
    };

    let history = settings::load_validation_log();
    let previous = audit::find_previous_entry(&history, kind, &host, port);

    let result = match check {
        Ok(result) => result,
        Err(error) => {
            // A failed handshake is a finding, not just an error: record it so
            // the next run can diff against it, then surface the failure.
            let entry = audit::build_failure_entry(
                kind,
                &host,
                port,
                verify,
                full_scan,
                error.to_string(),
                previous,
            );
            let _ = settings::append_validation_log_entry(&entry);
            return Err(error);
        }
    };

    let audit_entry =
        audit::build_success_entry(kind, &host, port, verify, full_scan, &result, previous);
    let _ = settings::append_validation_log_entry(&audit_entry);

    let exported_certs = match export_certs_dir {
        Some(dir) => endpoint::export_cert_chain_pem(&result, Path::new(dir))?
            .into_iter()
            .map(|p: PathBuf| p.display().to_string())
            .collect(),
        None => Vec::new(),
    };

    let (ldap_config, ldap_config_error) = match (protocol, ldap_config_test) {
        (EndpointProtocol::Ldaps, Some(test)) => {
            let bind_config = test.to_bind_config()?;
            let ldap_port = test.port.unwrap_or(port);
            match ssl_toolbox_core::ldap::check_base_config(&host, ldap_port, &bind_config) {
                Ok(config) => (Some(config), None),
                Err(error) => (None, Some(error.to_string())),
            }
        }
        _ => (None, None),
    };

    let host_key = match protocol {
        EndpointProtocol::Https => "https_host",
        EndpointProtocol::Ldaps => "ldaps_host",
        EndpointProtocol::Smtp => "smtp_host",
        EndpointProtocol::SqlServer => "sql_server_host",
    };

    Ok(OpResult {
        job: job(kind, format!("Verify {host}:{port}"))
            .input(host_key, &host)
            .replay("port", &port.to_string())
            .replay("full_scan", &full_scan.to_string())
            .replay("verify", &verify.to_string())
            .build(),
        outcome: OpOutcome::EndpointVerified(Box::new(EndpointVerification {
            protocol,
            host,
            port,
            result,
            audit: audit_entry,
            ldap_config,
            ldap_config_error,
            exported_certs,
        })),
    })
}

/// Small builder so each match arm reads as a description of the job rather
/// than four lines of map insertion.
struct JobBuilder {
    kind: ActionKind,
    summary: String,
    inputs: BTreeMap<String, String>,
    outputs: BTreeMap<String, String>,
    replay: BTreeMap<String, String>,
    transient: bool,
}

fn job(kind: ActionKind, summary: impl Into<String>) -> JobBuilder {
    JobBuilder {
        kind,
        summary: summary.into(),
        inputs: BTreeMap::new(),
        outputs: BTreeMap::new(),
        replay: BTreeMap::new(),
        transient: false,
    }
}

impl JobBuilder {
    fn input(mut self, key: &str, value: &str) -> Self {
        self.inputs.insert(key.to_string(), value.to_string());
        self
    }

    fn output(mut self, key: &str, value: &str) -> Self {
        self.outputs.insert(key.to_string(), value.to_string());
        self
    }

    fn replay(mut self, key: &str, value: &str) -> Self {
        self.replay.insert(key.to_string(), value.to_string());
        self
    }

    /// Mark this job as a read that should not enter recent-jobs history.
    fn transient(mut self) -> Self {
        self.transient = true;
        self
    }

    fn build(self) -> JobRecord {
        JobRecord {
            kind: self.kind,
            summary: self.summary,
            inputs: self.inputs,
            outputs: self.outputs,
            replay_data: self.replay,
            profile: None,
            transient: self.transient,
            timestamp_secs: now_secs(),
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

//! ssl-toolbox command-line interface.
//!
//! This binary is a thin front-end: it parses arguments, collects any
//! passphrases the operation needs, hands a single [`OpRequest`] to
//! `ssl-toolbox-ops`, and renders the structured result for a terminal. All
//! orchestration lives in the ops crate so the CLI and the GUI cannot drift
//! apart (ARCHITECTURE.md §2.1a, §10.6).

mod display;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use cliclack::{confirm, input, password, select};
use dotenvy::dotenv;
use std::path::Path;

use ssl_toolbox_core::{ConfigInputs, CsrDefaults, SanKind, SanName};
use ssl_toolbox_ops::endpoint::{EndpointProtocol, format_connect_target};
use ssl_toolbox_ops::ops::{LdapConfigTest, OpOutcome, OpRequest, OpResult};
use ssl_toolbox_ops::secret::Secret;
use ssl_toolbox_ops::{audit, credentials, settings};

#[derive(Parser)]
#[command(name = "ssl-toolbox", author, version, about = "SSL/TLS Security Toolbox", long_about = None)]
struct Cli {
    /// Enable debug output
    #[arg(long, global = true)]
    debug: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create an encrypted private key
    Key {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Generate a CSR from config using an existing key or create a new key if needed
    Generate {
        #[arg(short, long)]
        conf: String,
        #[arg(short, long)]
        key: String,
        #[arg(long)]
        csr: String,
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Create PFX from key and signed certificate
    Pfx {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        cert: String,
        #[arg(short, long)]
        out: String,
        #[arg(long)]
        chain: Option<String>,
        /// Use legacy TripleDES-SHA1 encryption for compatibility
        #[arg(long)]
        legacy: bool,
    },
    /// Convert existing PFX to legacy TripleDES-SHA1 format
    PfxLegacy {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        out: String,
    },
    /// Convert between certificate formats (PEM, DER, Base64)
    Convert {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
        /// Target format: pem, der, base64
        #[arg(short, long)]
        format: String,
    },
    /// Auto-detect certificate file format
    Identify {
        #[arg(short, long)]
        input: String,
        /// Save the result to a file
        #[arg(short, long)]
        out: Option<String>,
    },
    /// Generate a new OpenSSL configuration from scratch via interactive prompts
    NewConfig {
        #[arg(short, long)]
        out: Option<String>,
    },
    /// Print an existing OpenSSL config with a summary of what this tool reads from it
    ViewConfig {
        #[arg(short, long)]
        input: String,
        /// Save the config and its summary to a file
        #[arg(short, long)]
        out: Option<String>,
    },
    /// Replace an existing OpenSSL config, keeping the previous contents as <path>.bak
    ///
    /// The replacement text is read from --from, or from stdin when given `-`.
    SaveConfig {
        #[arg(short, long)]
        out: String,
        #[arg(long, default_value = "-")]
        from: String,
    },
    /// Generate OpenSSL configuration from existing certificate or CSR
    Config {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        out: String,
        #[arg(long)]
        is_csr: bool,
    },
    /// View details of a certificate
    ViewCert {
        #[arg(short, long)]
        input: String,
        /// Save the rendered details to a file
        #[arg(short, long)]
        out: Option<String>,
    },
    /// View details of a CSR
    ViewCsr {
        #[arg(short, long)]
        input: String,
        /// Save the rendered details to a file
        #[arg(short, long)]
        out: Option<String>,
    },
    /// View contents of a PFX/PKCS12 file
    ViewPfx {
        #[arg(short, long)]
        input: String,
        /// Save the rendered details to a file
        #[arg(short, long)]
        out: Option<String>,
    },
    /// Verify TLS certificate and protocol for an HTTPS endpoint
    VerifyHttps {
        #[arg(short = 'H', long)]
        host: String,
        #[arg(short, long, default_value = "443")]
        port: u16,
        /// Skip certificate validation
        #[arg(long)]
        no_verify: bool,
        /// Probe each protocol version against the locally testable cipher-suite set
        #[arg(long)]
        full_scan: bool,
        /// Save results to a file
        #[arg(short, long)]
        out: Option<String>,
        /// Export returned certificate chain as one PEM file per certificate into DIR
        #[arg(long, value_name = "DIR")]
        export_certs: Option<String>,
    },
    /// Verify TLS certificate and protocol for an LDAPS endpoint
    VerifyLdaps {
        #[arg(short = 'H', long)]
        host: String,
        #[arg(short, long, default_value = "636")]
        port: u16,
        /// Skip certificate validation
        #[arg(long)]
        no_verify: bool,
        /// Probe each protocol version against the locally testable cipher-suite set
        #[arg(long)]
        full_scan: bool,
        /// Also run an anonymous or authenticated RootDSE base search over LDAPS
        #[arg(long)]
        ldap_config_test: bool,
        /// Override the LDAPS port for --ldap-config-test
        #[arg(long, requires = "ldap_config_test")]
        ldap_port: Option<u16>,
        /// Bind DN for authenticated RootDSE search
        #[arg(long, requires = "ldap_config_test")]
        ldap_bind_dn: Option<String>,
        /// Password for --ldap-bind-dn
        #[arg(long, requires = "ldap_config_test")]
        ldap_bind_password: Option<String>,
        /// Save results to a file
        #[arg(short, long)]
        out: Option<String>,
        /// Export returned certificate chain as one PEM file per certificate into DIR
        #[arg(long, value_name = "DIR")]
        export_certs: Option<String>,
    },
    /// Verify TLS certificate via SMTP STARTTLS
    VerifySmtp {
        #[arg(short = 'H', long)]
        host: String,
        #[arg(short, long, default_value = "587")]
        port: u16,
        /// Skip certificate validation
        #[arg(long)]
        no_verify: bool,
        /// Save results to a file
        #[arg(short, long)]
        out: Option<String>,
    },
    /// Verify the certificate SQL Server presents after TDS encryption negotiation
    VerifySqlServer {
        #[arg(short = 'H', long)]
        host: String,
        #[arg(short, long, default_value = "1433")]
        port: u16,
        /// Skip certificate validation
        #[arg(long)]
        no_verify: bool,
        /// Save results to a file
        #[arg(short, long)]
        out: Option<String>,
        /// Export returned certificate chain as one PEM file per certificate into DIR
        #[arg(long, value_name = "DIR")]
        export_certs: Option<String>,
    },
    /// Initialize config files in .ssl-toolbox/ directory
    Init {
        /// Create config in ~/.ssl-toolbox/ instead of ./.ssl-toolbox/
        #[arg(long)]
        global: bool,
    },
    /// CA operations (requires CA plugin)
    #[command(subcommand)]
    Ca(CaCommands),
}

#[derive(Subcommand)]
enum CaCommands {
    /// List available certificate profiles
    ListProfiles {
        /// Save the profile list to a file
        #[arg(short, long)]
        out: Option<String>,
    },
    /// Find issued certificates at the CA
    Search {
        /// Match on common name
        #[arg(long)]
        common_name: Option<String>,
        /// Match on a subject alternative name
        #[arg(long)]
        san: Option<String>,
        /// Match on serial number
        #[arg(long)]
        serial: Option<String>,
        /// Vendor status label, e.g. Issued or Revoked
        #[arg(long)]
        status: Option<String>,
        /// Restrict to one certificate profile ID
        #[arg(long)]
        profile_id: Option<String>,
        /// Results per page
        #[arg(long)]
        size: Option<u32>,
        /// Offset of the first result
        #[arg(long)]
        position: Option<u32>,
        /// Skip the per-result lookup that fills in status and dates
        #[arg(long)]
        no_dates: bool,
        /// Save the results to a file
        #[arg(short, long)]
        out: Option<String>,
    },
    /// Show the full record for one certificate by its ID
    Show {
        #[arg(short, long)]
        id: String,
        /// Save the record to a file
        #[arg(short, long)]
        out: Option<String>,
    },
    /// List CSRs previously submitted from this workspace
    Requests {
        /// Save the list to a file
        #[arg(short, long)]
        out: Option<String>,
    },
    /// Submit CSR to CA for signing
    Submit {
        #[arg(short, long)]
        csr: String,
        /// Also write the returned request ID here. The ID is recorded in the
        /// workspace either way — see `ca requests`.
        #[arg(short, long)]
        out: Option<String>,
        #[arg(short, long)]
        description: Option<String>,
        #[arg(short, long)]
        product_code: Option<String>,
        /// Certificate lifetime in days; must be one the profile allows
        #[arg(long)]
        term_days: Option<i32>,
    },
    /// Collect/download a signed certificate by request ID
    Collect {
        #[arg(short, long)]
        id: String,
        #[arg(short, long)]
        out: String,
        /// cert, cert-issuer-after, chain, pkcs7, pkcs7-pem, intermediates, root-first
        #[arg(short, long, default_value = "chain", value_parser = parse_collect_format)]
        format: String,
    },
    /// Show CA endpoint settings and where credentials are coming from
    Settings {
        /// Save the summary to a file
        #[arg(short, long)]
        out: Option<String>,
    },
    /// Write CA endpoint settings to ~/.ssl-toolbox/sectigo.json
    Configure {
        #[arg(long)]
        api_base: Option<String>,
        #[arg(long)]
        org_id: Option<String>,
        #[arg(long)]
        product_code: Option<String>,
        #[arg(long)]
        token_url: Option<String>,
    },
    /// Store a client ID and secret in the encrypted credential vault
    Login {
        #[arg(long)]
        client_id: Option<String>,
    },
    /// Delete the credential vault
    Logout,
    /// Authenticate against the CA without performing an operation
    TestConnection,
}

fn main() -> Result<()> {
    let _ = dotenv();
    let cli = Cli::parse();
    execute_command(cli.command, cli.debug)
}

fn execute_command(cmd: Commands, debug: bool) -> Result<()> {
    match cmd {
        Commands::Key { key, password: pw } => {
            let password = match pw {
                Some(value) => Secret::new(value),
                None => prompt_new_password("Enter password for private key")?,
            };
            report(ssl_toolbox_ops::run(OpRequest::CreateKey {
                out: key,
                password,
            })?);
        }

        Commands::Generate {
            conf,
            key,
            csr,
            password: pw,
        } => {
            let key_exists = Path::new(&key).exists();
            let key_password = match pw {
                Some(value) => Secret::new(value),
                None if key_exists => {
                    prompt_optional_password("Enter password for existing private key")?
                }
                None => {
                    println!("Private key {key} does not exist and will be created.");
                    prompt_new_password("Enter password for the new private key")?
                }
            };

            report(ssl_toolbox_ops::run(OpRequest::GenerateCsr {
                conf,
                key,
                csr,
                key_password,
                create_key_if_missing: true,
            })?);
        }

        Commands::Pfx {
            key,
            cert,
            out,
            chain,
            legacy,
        } => {
            println!(
                "Note: If your private key is encrypted, you'll be prompted for its password."
            );
            println!("If not encrypted, just press Enter when prompted.");
            let key_password = prompt_optional_password(
                "Enter password for private key (or press Enter if not encrypted)",
            )?;
            let pfx_password = prompt_new_password("Enter password for PFX export")?;

            report(ssl_toolbox_ops::run(OpRequest::CreatePfx {
                key,
                cert,
                chain,
                out,
                key_password,
                pfx_password,
                legacy,
            })?);
        }

        Commands::PfxLegacy { input, out } => {
            let input_password = prompt_new_password("Enter password for input PFX")?;
            let output_password = prompt_new_password("Enter password for output PFX")?;
            report(ssl_toolbox_ops::run(OpRequest::ConvertPfxToLegacy {
                input,
                out,
                input_password,
                output_password,
            })?);
        }

        Commands::Convert {
            input,
            output,
            format,
        } => {
            report(ssl_toolbox_ops::run(OpRequest::ConvertFormat {
                input,
                output,
                format,
            })?);
        }

        Commands::Identify { input, out } => {
            report_saving(
                ssl_toolbox_ops::run(OpRequest::IdentifyFormat { input })?,
                out.as_deref(),
            )?;
        }

        Commands::ViewConfig { input, out } => {
            report_saving(
                ssl_toolbox_ops::run(OpRequest::LoadConfig { path: input })?,
                out.as_deref(),
            )?;
        }

        Commands::SaveConfig { out, from } => {
            let text = if from == "-" {
                let mut buffer = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut buffer)
                    .context("Could not read replacement config text from stdin")?;
                buffer
            } else {
                std::fs::read_to_string(&from)
                    .with_context(|| format!("Could not read replacement config text {from}"))?
            };
            report(ssl_toolbox_ops::run(OpRequest::SaveConfig {
                path: out,
                text,
            })?);
        }

        Commands::NewConfig { out } => {
            let app_config = settings::load_config();
            let inputs = prompt_config_inputs(&app_config.csr_defaults)?;
            let output_path = match out {
                Some(path) => path,
                None => input("Output .cnf file path")
                    .default_input(&format!("{}.cnf", inputs.common_name))
                    .interact()?,
            };

            print_config_summary(&inputs, &output_path);
            if !confirm("Write this config file?").interact()? {
                println!("Cancelled.");
                return Ok(());
            }

            report(ssl_toolbox_ops::run(OpRequest::GenerateConfig {
                inputs: Box::new(inputs),
                out: output_path,
            })?);
        }

        Commands::Config {
            input: input_path,
            out,
            is_csr,
        } => {
            report(ssl_toolbox_ops::run(
                OpRequest::GenerateConfigFromCertOrCsr {
                    input: input_path,
                    out,
                    is_csr,
                },
            )?);
        }

        Commands::ViewCert { input, out } => {
            report_saving(
                ssl_toolbox_ops::run(OpRequest::InspectCert {
                    input: input_source(input),
                })?,
                out.as_deref(),
            )?;
        }

        Commands::ViewCsr { input, out } => {
            report_saving(
                ssl_toolbox_ops::run(OpRequest::InspectCsr {
                    input: input_source(input),
                })?,
                out.as_deref(),
            )?;
        }

        Commands::ViewPfx { input, out } => {
            let password = prompt_new_password("Enter PFX password")?;
            report_saving(
                ssl_toolbox_ops::run(OpRequest::InspectPfx { input, password })?,
                out.as_deref(),
            )?;
        }

        Commands::VerifyHttps {
            host,
            port,
            no_verify,
            full_scan,
            out,
            export_certs,
        } => {
            verify(
                EndpointProtocol::Https,
                host,
                port,
                443,
                !no_verify,
                full_scan,
                export_certs,
                None,
                out,
            )?;
        }

        Commands::VerifyLdaps {
            host,
            port,
            no_verify,
            full_scan,
            ldap_config_test,
            ldap_port,
            ldap_bind_dn,
            ldap_bind_password,
            out,
            export_certs,
        } => {
            let probe = if ldap_config_test {
                let bind_password = match (&ldap_bind_dn, ldap_bind_password) {
                    (Some(_), Some(value)) => Some(Secret::new(value)),
                    (Some(dn), None) => Some(prompt_new_password(&format!(
                        "Enter LDAP bind password for {dn}"
                    ))?),
                    _ => None,
                };
                Some(LdapConfigTest {
                    port: ldap_port,
                    bind_dn: ldap_bind_dn,
                    bind_password,
                })
            } else {
                None
            };

            verify(
                EndpointProtocol::Ldaps,
                host,
                port,
                636,
                !no_verify,
                full_scan,
                export_certs,
                probe,
                out,
            )?;
        }

        Commands::VerifySmtp {
            host,
            port,
            no_verify,
            out,
        } => {
            verify(
                EndpointProtocol::Smtp,
                host,
                port,
                587,
                !no_verify,
                false,
                None,
                None,
                out,
            )?;
        }

        Commands::VerifySqlServer {
            host,
            port,
            no_verify,
            out,
            export_certs,
        } => {
            verify(
                EndpointProtocol::SqlServer,
                host,
                port,
                1433,
                !no_verify,
                false,
                export_certs,
                None,
                out,
            )?;
        }

        Commands::Init { global } => {
            let dir = if global {
                let home = std::env::var_os("HOME")
                    .or_else(|| std::env::var_os("USERPROFILE"))
                    .map(std::path::PathBuf::from)
                    .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
                home.join(".ssl-toolbox")
            } else {
                std::path::PathBuf::from(".ssl-toolbox")
            };

            let written = settings::init_config(&dir)?;
            if written.is_empty() {
                println!("Config files already exist in {}", dir.display());
            } else {
                for path in &written {
                    println!("Created: {}", path.display());
                }
                println!(
                    "\nEdit these files to set your organization defaults, then re-run ssl-toolbox."
                );
            }
        }

        Commands::Ca(ca_cmd) => execute_ca_command(ca_cmd, debug)?,
    }

    Ok(())
}

/// Run an endpoint verification and render it, optionally saving the report.
#[allow(clippy::too_many_arguments)]
fn verify(
    protocol: EndpointProtocol,
    host: String,
    port: u16,
    default_port: u16,
    verify_cert: bool,
    full_scan: bool,
    export_certs: Option<String>,
    ldap_config_test: Option<LdapConfigTest>,
    out: Option<String>,
) -> Result<()> {
    // Only forward an explicit port; leaving it unset lets a `host:port` string
    // supply the port instead.
    let explicit_port = (port != default_port).then_some(port);

    println!(
        "\nConnecting to {}:{}...",
        format_connect_target(&host),
        port
    );

    let result = ssl_toolbox_ops::run(OpRequest::VerifyEndpoint {
        protocol,
        host,
        port: explicit_port,
        verify: verify_cert,
        full_scan,
        export_certs_dir: export_certs,
        ldap_config_test,
    });

    let result = match result {
        Ok(result) => result,
        Err(error) => {
            // The failure is already recorded in the validation log by ops.
            eprintln!("Error: {error}");
            return Ok(());
        }
    };

    let OpOutcome::EndpointVerified(verification) = result.outcome else {
        unreachable!("VerifyEndpoint always yields EndpointVerified");
    };

    let mut report_text =
        display::render_tls_check_result(&verification.result, protocol.report_title());

    if let Some(config) = &verification.ldap_config {
        report_text.push_str(&display::render_ldap_config_check_result(config));
    } else if let Some(error) = &verification.ldap_config_error {
        report_text.push_str(&display::render_ldap_config_check_error(
            &verification.host,
            verification.port,
            "RootDSE base search",
            error,
        ));
    }

    if let Some(path) = out.as_deref() {
        std::fs::write(
            path,
            render_verify_results_report(&report_text, Some(&verification.audit)),
        )
        .with_context(|| format!("Failed to write verify results to {path}"))?;
        println!("Saved report to {path}");
    }

    if !verification.exported_certs.is_empty() {
        println!("Exported certificates:");
        for path in &verification.exported_certs {
            println!("  - {path}");
        }
    } else if verification.result.cert_chain_pem.is_empty() {
        println!("Exported certificates: no certificates presented by server");
    }

    print_validation_audit_feedback(&verification.audit);
    print!("{report_text}");

    Ok(())
}

/// Validate `--format` while clap is still parsing arguments.
///
/// Ops validates the format too, for the GUI's benefit — but by the time a
/// request reaches ops the CLI has already run its credential pre-flight, so a
/// typo would surface as "no credentials configured" and send the operator to
/// fix something unrelated. Rejecting it here keeps the error about the typo.
fn parse_collect_format(value: &str) -> Result<String, String> {
    match ssl_toolbox_ops::CollectFormat::parse(value) {
        Some(format) => Ok(format.token().to_string()),
        None => Err(format!(
            "unknown format '{value}'. Use one of: {}",
            ssl_toolbox_ops::CollectFormat::ALL
                .map(|format| format.token())
                .join(", ")
        )),
    }
}

/// Treat a CLI `--input` as a file path.
///
/// The desktop app can also hand ops pasted text; the terminal has a better
/// answer for that already — shell redirection into a file — so the CLI stays
/// path-only rather than growing a flag that competes with `<`.
fn input_source(path: String) -> ssl_toolbox_ops::ops::InputSource {
    ssl_toolbox_ops::ops::InputSource::Path { path }
}

/// Print the outcome of a non-verification operation.
fn report(result: OpResult) {
    print!("{}", render_outcome(result.outcome));
}

/// Print an outcome and, when `out` is given, save the same text to a file.
///
/// Every command that renders a report takes `--out`, so a result can be
/// attached to a ticket or kept as evidence without the operator re-running it
/// under `tee`. The file receives exactly what the terminal received: a second,
/// prettier format would be a second thing to keep correct.
fn report_saving(result: OpResult, out: Option<&str>) -> Result<()> {
    let rendered = render_outcome(result.outcome);
    print!("{rendered}");
    if let Some(path) = out {
        std::fs::write(path, &rendered)
            .with_context(|| format!("Failed to write output to {path}"))?;
        println!("Saved output to {path}");
    }
    Ok(())
}

/// Render the outcome of a non-verification operation as text.
///
/// Returning a string rather than printing is what makes `--out` possible at
/// all; `report` is the thin printing wrapper over it.
fn render_outcome(outcome: OpOutcome) -> String {
    match outcome {
        OpOutcome::KeyCreated { path } => format!("Success: Generated {path}\n"),
        OpOutcome::CsrGenerated {
            csr_path,
            key_path,
            key_created,
            ..
        } => {
            if key_created {
                format!("Success: Generated {key_path} and {csr_path}\n")
            } else {
                format!("Success: Generated {csr_path}\n")
            }
        }
        OpOutcome::PfxCreated { path, legacy } => {
            if legacy {
                format!("Success: Legacy PFX (TripleDES-SHA1) created at {path}\n")
            } else {
                format!("Success: PFX created at {path}\n")
            }
        }
        OpOutcome::ConfigWritten { path } => {
            format!("Success: OpenSSL config written to {path}\n")
        }
        OpOutcome::ConfigLoaded {
            path,
            text,
            summary,
        } => format!(
            "{text}\n{}",
            display::render_config_summary(&summary, &path)
        ),
        OpOutcome::ConfigSaved {
            path,
            backup,
            summary,
        } => {
            let mut rendered = String::new();
            if let Some(backup) = &backup {
                rendered.push_str(&format!("Previous contents saved to {backup}\n"));
            }
            rendered.push_str(&format!("Success: OpenSSL config written to {path}\n"));
            rendered.push_str(&display::render_config_summary(&summary, &path));
            rendered
        }
        OpOutcome::CertInspected { chain, .. } => {
            display::render_cert_details_list(&chain, "Certificate Details")
        }
        OpOutcome::CsrInspected {
            common_name, sans, ..
        } => render_csr_details(&common_name, &sans),
        OpOutcome::PfxInspected { details, .. } => {
            display::render_pfx_details(&details, "PFX Contents")
        }
        OpOutcome::FormatConverted { output, format } => {
            format!("Success: Converted to {format}: {output}\n")
        }
        OpOutcome::FormatIdentified {
            path, description, ..
        } => format!("File: {path}\nFormat: {description}\n"),
        OpOutcome::CaProfilesListed { provider, profiles } => {
            let mut rendered = format!("\nAvailable certificate profiles from {provider}:\n\n");
            for profile in &profiles {
                rendered.push_str(&format!("  [{}] {}\n", profile.id, profile.name));
                if let Some(description) = &profile.description {
                    rendered.push_str(&format!("      {description}\n"));
                }
                if !profile.terms.is_empty() {
                    rendered.push_str(&format!("      Terms (days): {:?}\n", profile.terms));
                }
            }
            rendered.push('\n');
            rendered
        }
        OpOutcome::CaCsrSubmitted { request_id, path } => match path {
            Some(path) => {
                format!("Success: CSR submitted. Request ID {request_id} saved to {path}\n")
            }
            None => format!(
                "Success: CSR submitted. Request ID {request_id}\n\
                 Recorded in the workspace; `ssl-toolbox ca requests` lists it again.\n"
            ),
        },
        OpOutcome::CaCertCollected { path, .. } => {
            format!("Success: Certificate collected to {path}\n")
        }
        OpOutcome::CaCertificatesFound {
            provider,
            certificates,
            position,
            may_have_more,
        } => render_certificate_search(&provider, &certificates, position, may_have_more),
        OpOutcome::CaCertificateLoaded { certificate, .. } => {
            render_certificate_details(&certificate)
        }
        OpOutcome::CaRequestsListed { requests } => render_ca_requests(&requests),
        OpOutcome::CaSettingsLoaded(view) => render_ca_settings(&view),
        OpOutcome::CaSettingsSaved { path, shadowed_by } => {
            let mut rendered = format!("Success: CA settings saved to {path}\n");
            if let Some(shadow) = shadowed_by {
                rendered.push_str(&format!(
                    "Warning: {shadow} is a project-scope config and overrides these values here.\n"
                ));
            }
            rendered
        }
        OpOutcome::CaCredentialsChanged { status } => render_credential_status(&status),
        OpOutcome::CaConnectionVerified { provider, source } => format!(
            "Success: authenticated with {provider} using credentials from {}\n",
            describe_credential_source(source)
        ),
        OpOutcome::EndpointVerified(_) => {
            unreachable!("endpoint verification is rendered by `verify`")
        }
    }
}

fn render_csr_details(common_name: &str, sans: &[String]) -> String {
    let mut rendered = String::new();
    rendered.push_str("\n╔═══════════════════════════════════════════════════════════════╗\n");
    rendered.push_str("║                        CSR Details                           ║\n");
    rendered.push_str("╚═══════════════════════════════════════════════════════════════╝\n\n");
    rendered.push_str(&format!("  CommonName: {common_name}\n"));
    if sans.is_empty() {
        rendered.push_str("  SANs: None\n");
    } else {
        rendered.push_str("  SANs:\n");
        for san in sans {
            rendered.push_str(&format!("    • {san}\n"));
        }
    }
    rendered.push('\n');
    rendered
}

fn describe_credential_source(source: credentials::CredentialSource) -> &'static str {
    match source {
        credentials::CredentialSource::Environment => "environment variables",
        credentials::CredentialSource::Vault => "the credential vault",
    }
}

fn render_ca_settings(view: &ssl_toolbox_ops::ops::CaSettingsView) -> String {
    let mut out = String::from("\n");
    match &view.provider {
        Some(provider) => out.push_str(&format!("CA provider:   {provider}\n")),
        None => out.push_str("CA provider:   none (built without a CA plugin)\n"),
    }
    out.push_str(&format!("API base:      {}\n", or_unset(&view.api_base)));
    out.push_str(&format!("Organisation:  {}\n", or_unset(&view.org_id)));
    out.push_str(&format!(
        "Product code:  {}\n",
        or_unset(&view.product_code)
    ));
    out.push_str(&format!("Token URL:     {}\n", or_unset(&view.token_url)));
    if let Some(path) = &view.config_path {
        out.push_str(&format!("Settings file: {path}\n"));
    }
    if let Some(shadow) = &view.shadowed_by {
        out.push_str(&format!("Overridden by: {shadow} (project scope)\n"));
    }
    if !view.environment_overrides.is_empty() {
        out.push_str(&format!(
            "Env overrides: {} (these win over the settings file)\n",
            view.environment_overrides.join(", ")
        ));
    }
    out.push('\n');
    out.push_str(&render_credential_status(&view.credentials));
    out
}

fn or_unset(value: &str) -> &str {
    if value.is_empty() { "(not set)" } else { value }
}

fn render_certificate_search(
    provider: &str,
    certificates: &[ssl_toolbox_ops::CertificateSummary],
    position: u32,
    may_have_more: bool,
) -> String {
    if certificates.is_empty() {
        return format!("\nNo certificates at {provider} matched.\n\n");
    }

    let mut out = format!(
        "\n{} certificate(s) from {provider}, starting at {position}:\n\n",
        certificates.len()
    );
    for certificate in certificates {
        out.push_str(&format!(
            "  [{}] {}\n",
            certificate.id, certificate.common_name
        ));
        // Status and validity decide whether a row is the certificate being
        // looked for, so they sit directly under the name rather than behind a
        // second command.
        let mut facts: Vec<String> = Vec::new();
        if let Some(status) = &certificate.status {
            facts.push(format!("Status: {status}"));
        }
        if let Some(requested) = &certificate.requested {
            facts.push(format!("Requested: {requested}"));
        }
        if let Some(expires) = &certificate.expires {
            facts.push(format!("Expires: {expires}"));
        }
        if !facts.is_empty() {
            out.push_str(&format!("      {}\n", facts.join("   ")));
        }
        if !certificate.serial_number.is_empty() {
            out.push_str(&format!("      Serial: {}\n", certificate.serial_number));
        }
        for san in &certificate.subject_alternative_names {
            out.push_str(&format!("      SAN:    {san}\n"));
        }
    }
    if may_have_more {
        // The API reports no total, so a full page means "maybe more", never
        // "definitely more" — say which of the two this is.
        out.push_str(&format!(
            "\nThe page came back full; there may be more. Re-run with --position {}.\n",
            position + certificates.len() as u32
        ));
    }
    out.push('\n');
    out
}

fn render_certificate_details(certificate: &ssl_toolbox_ops::CertificateDetails) -> String {
    let mut out = format!("\nCertificate {}\n\n", certificate.id);
    let mut row = |label: &str, value: &str| {
        if !value.is_empty() {
            out.push_str(&format!("  {label:<14}{value}\n"));
        }
    };
    row("Common name:", &certificate.common_name);
    row("Serial:", &certificate.serial_number);
    row("Status:", certificate.status.as_deref().unwrap_or_default());
    row(
        "Profile:",
        certificate.profile.as_deref().unwrap_or_default(),
    );
    row(
        "Term:",
        &certificate
            .term_days
            .map(|days| format!("{days} days"))
            .unwrap_or_default(),
    );
    row(
        "Requested:",
        certificate.requested.as_deref().unwrap_or_default(),
    );
    row(
        "Expires:",
        certificate.expires.as_deref().unwrap_or_default(),
    );
    row(
        "Requester:",
        certificate.requester.as_deref().unwrap_or_default(),
    );
    row(
        "Key:",
        certificate.key_algorithm.as_deref().unwrap_or_default(),
    );
    row(
        "Comments:",
        certificate.comments.as_deref().unwrap_or_default(),
    );

    if !certificate.subject_alternative_names.is_empty() {
        out.push_str("  SANs:\n");
        for san in &certificate.subject_alternative_names {
            out.push_str(&format!("    • {san}\n"));
        }
    }
    out.push('\n');
    out
}

/// Past CA submissions, newest first.
///
/// The desktop app offers these as a dropdown on its collect screen; the CLI
/// has no dropdown, so it gets the same list as text — otherwise an operator who
/// submitted from the app could not find the ID from the terminal.
fn render_ca_requests(requests: &[ssl_toolbox_ops::workflow::CaRequestRecord]) -> String {
    if requests.is_empty() {
        return "No CA submissions recorded yet.\n".to_string();
    }

    let mut out = String::from("\nRecorded CA submissions (newest first):\n\n");
    for record in requests {
        out.push_str(&format!("  {}\n", record.request_id));
        if !record.common_name.is_empty() {
            out.push_str(&format!("      Subject:     {}\n", record.common_name));
        }
        if !record.description.is_empty() {
            out.push_str(&format!("      Description: {}\n", record.description));
        }
        if !record.profile.is_empty() {
            out.push_str(&format!("      Profile:     {}\n", record.profile));
        }
        if !record.csr_path.is_empty() {
            out.push_str(&format!("      CSR:         {}\n", record.csr_path));
        }
        out.push_str(&format!(
            "      Submitted:   {}\n",
            audit::format_timestamp_utc(record.timestamp_secs)
        ));
    }
    out.push('\n');
    out
}

/// Report the credential situation without printing the credential.
///
/// Only the client ID's length is shown — ARCHITECTURE.md §11.3 rule 1 keeps
/// the value itself off stdout even under `--debug`.
fn render_credential_status(status: &credentials::CredentialStatus) -> String {
    let mut out = String::new();

    if let Some(problem) = &status.problem {
        out.push_str(&format!("Credentials:   unusable — {problem}\n"));
        if let Some(path) = &status.vault_path {
            out.push_str(&format!(
                "Vault:         {path}{}\n",
                if status.vault_present {
                    " (present, but the environment override takes precedence)"
                } else {
                    " (not created)"
                }
            ));
        }
        return out;
    }

    match status.active_source {
        Some(source) => {
            out.push_str(&format!(
                "Credentials:   in use, from {}\n",
                describe_credential_source(source)
            ));
            if let Some(length) = status.client_id_length {
                out.push_str(&format!(
                    "Client ID:     {length} characters (value withheld)\n"
                ));
            }
        }
        None if status.vault_present => {
            out.push_str("Credentials:   stored but locked — unlock with the vault passphrase\n");
        }
        None => {
            out.push_str("Credentials:   none configured — run `ssl-toolbox ca login`\n");
        }
    }

    if status.environment_override && status.vault_present {
        out.push_str(
            "Note:          SCM_CLIENT_ID / SCM_CLIENT_SECRET are set and take precedence over the vault.\n",
        );
    }
    if let Some(path) = &status.vault_path {
        out.push_str(&format!(
            "Vault:         {path}{}\n",
            if status.vault_present {
                ""
            } else {
                " (not created)"
            }
        ));
    }

    out
}

fn prompt_new_password(label: &str) -> Result<Secret> {
    Ok(Secret::new(password(label).interact()?))
}

/// Prompt where an empty answer legitimately means "not encrypted".
fn prompt_optional_password(label: &str) -> Result<Secret> {
    Ok(Secret::new(
        password(label).allow_empty().interact()? as String
    ))
}

fn prompt_config_inputs(defaults: &CsrDefaults) -> Result<ConfigInputs> {
    let common_name: String = input("Common Name").interact()?;

    let with_default = |label: &str, default: &str| -> Result<String> {
        Ok(if default.is_empty() {
            input(label).interact()?
        } else {
            input(label).default_input(default).interact()?
        })
    };

    let country = with_default("Country (2-letter code)", &defaults.country)?;
    let state = with_default("State or Province", &defaults.state)?;
    let locality = with_default("Locality / City", &defaults.locality)?;
    let organization = with_default("Organization", &defaults.organization)?;
    let org_unit = with_default("Organizational Unit", &defaults.org_unit)?;
    let email = with_default("Email Address", &defaults.email)?;

    // One entry at a time, type chosen per entry — the same model as the GUI's
    // SAN rows, so neither front-end infers a type from which field was used.
    let mut sans: Vec<SanName> = Vec::new();
    println!("\nSubject alternative names (the CN is already included as DNS.1).");
    println!("Press Enter with no value when done.");
    loop {
        let value: String = input("SAN value (or Enter to finish)")
            .required(false)
            .interact()?;
        if value.is_empty() {
            break;
        }
        let mut picker = select("Type for this SAN");
        for kind in SanKind::ALL {
            picker = picker.item(kind, kind.label(), kind.config_key());
        }
        let kind: SanKind = picker.interact()?;
        sans.push(SanName::new(kind, value));
    }

    let key_size: u32 = select("Key size")
        .item(2048, "2048", "Default — widely compatible")
        .item(4096, "4096", "Stronger but slower")
        .interact()?;

    let extended_key_usage: String = select("Extended Key Usage")
        .item(
            "serverAuth".to_string(),
            "Server Auth",
            "TLS server certificates",
        )
        .item(
            "clientAuth".to_string(),
            "Client Auth",
            "TLS client certificates",
        )
        .item(
            "serverAuth, clientAuth".to_string(),
            "Both (mTLS)",
            "Mutual TLS — server and client auth",
        )
        .interact()?;

    Ok(ConfigInputs {
        common_name,
        country,
        state,
        locality,
        organization,
        org_unit,
        email,
        sans,
        key_size,
        extended_key_usage,
    })
}

fn print_config_summary(inputs: &ConfigInputs, output_path: &str) {
    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║                   Config Summary                            ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");
    println!("  CN:           {}", inputs.common_name);
    println!("  Country:      {}", inputs.country);
    println!("  State:        {}", inputs.state);
    println!("  Locality:     {}", inputs.locality);
    println!("  Org:          {}", inputs.organization);
    println!("  OU:           {}", inputs.org_unit);
    println!("  Email:        {}", inputs.email);
    println!("  Key Size:     {}", inputs.key_size);
    println!("  Ext Key Use:  {}", inputs.extended_key_usage);
    println!("  SANs:");
    println!("    DNS.1 = {} (from CN)", inputs.common_name);
    let mut counters: Vec<(SanKind, usize)> = vec![(SanKind::Dns, 1)];
    for san in &inputs.sans {
        let index = match counters.iter_mut().find(|(kind, _)| *kind == san.kind) {
            Some(slot) => {
                slot.1 += 1;
                slot.1
            }
            None => {
                counters.push((san.kind, 1));
                1
            }
        };
        println!("    {}.{} = {}", san.kind.config_key(), index, san.value);
    }
    println!("  Output:       {}", output_path);
    println!();
}

fn execute_ca_command(cmd: CaCommands, debug: bool) -> Result<()> {
    // Handled before the shared path below: these three collect a secret or
    // edit configuration rather than reaching the CA, so they must not trigger
    // the unlock prompt that a CA call needs.
    match cmd {
        CaCommands::Login { client_id } => return ca_login(client_id),
        CaCommands::Logout => {
            report(ssl_toolbox_ops::run(OpRequest::CaClearCredentials)?);
            return Ok(());
        }
        CaCommands::Configure {
            api_base,
            org_id,
            product_code,
            token_url,
        } => return ca_configure(api_base, org_id, product_code, token_url),
        CaCommands::Settings { out } => {
            return report_saving(
                ssl_toolbox_ops::run(OpRequest::CaLoadSettings)?,
                out.as_deref(),
            );
        }
        // Reads the local workspace, not the CA — no credentials needed.
        CaCommands::Requests { out } => {
            return report_saving(
                ssl_toolbox_ops::run(OpRequest::CaListRequests)?,
                out.as_deref(),
            );
        }
        _ => {}
    }

    // Every remaining command talks to the CA, so it needs credentials in hand.
    // A CLI process starts locked; prompting here is the terminal's equivalent
    // of the desktop app's unlock dialog.
    ensure_ca_credentials()?;

    // `--out` on a CA read means "save the report"; on submit and collect it
    // names the artifact the operation produces, so only the reads route
    // through `report_saving`.
    let mut save_report_to: Option<String> = None;
    let request = match cmd {
        CaCommands::ListProfiles { out } => {
            save_report_to = out;
            OpRequest::CaListProfiles { debug }
        }
        CaCommands::Search {
            common_name,
            san,
            serial,
            status,
            profile_id,
            size,
            position,
            no_dates,
            out,
        } => {
            save_report_to = out;
            OpRequest::CaSearchCertificates {
                common_name,
                subject_alternative_name: san,
                serial_number: serial,
                status,
                profile_id,
                size,
                position,
                include_dates: !no_dates,
                debug,
            }
        }
        CaCommands::Show { id, out } => {
            save_report_to = out;
            OpRequest::CaCertificateDetails {
                certificate_id: id,
                debug,
            }
        }
        CaCommands::Submit {
            csr,
            out,
            description,
            product_code,
            term_days,
        } => OpRequest::CaSubmitCsr {
            csr,
            out,
            description,
            product_code,
            term_days,
            debug,
        },
        CaCommands::Collect { id, out, format } => OpRequest::CaCollectCert {
            request_id: id,
            out,
            format,
            debug,
        },
        CaCommands::TestConnection => OpRequest::CaTestConnection { debug },
        CaCommands::Login { .. }
        | CaCommands::Logout
        | CaCommands::Configure { .. }
        | CaCommands::Requests { .. }
        | CaCommands::Settings { .. } => unreachable!("handled above"),
    };

    report_saving(ssl_toolbox_ops::run(request)?, save_report_to.as_deref())
}

/// Make credentials available for a CA call, prompting to unlock if needed.
///
/// The four cases come from `credentials::availability` rather than being
/// re-derived here. An earlier version inspected the individual status flags and
/// collapsed a half-set environment override into "nothing configured", which
/// pointed the operator at `ca login` when the actual fix was to export the
/// second variable.
fn ensure_ca_credentials() -> Result<()> {
    match credentials::availability() {
        credentials::Availability::Ready(..) => Ok(()),
        credentials::Availability::Misconfigured(reason) => anyhow::bail!(reason),
        credentials::Availability::Missing => anyhow::bail!(
            "No CA credentials configured. Run `ssl-toolbox ca login`, or set SCM_CLIENT_ID and SCM_CLIENT_SECRET."
        ),
        credentials::Availability::Locked => {
            let passphrase = prompt_new_password("Vault passphrase")?;
            report(ssl_toolbox_ops::run(OpRequest::CaUnlockCredentials {
                vault_passphrase: passphrase,
            })?);
            Ok(())
        }
    }
}

fn ca_login(client_id: Option<String>) -> Result<()> {
    let client_id = match client_id {
        Some(value) => value,
        None => input("Client ID").interact()?,
    };
    let client_secret = prompt_new_password("Client secret")?;

    // Confirm the passphrase: it is the only key to the vault, and a typo here
    // is not recoverable — it produces a file nobody can open.
    let vault_passphrase =
        prompt_new_password("Vault passphrase (encrypts the stored credentials)")?;
    let confirm = prompt_new_password("Confirm vault passphrase")?;
    if vault_passphrase.expose() != confirm.expose() {
        anyhow::bail!("Vault passphrases do not match");
    }

    report(ssl_toolbox_ops::run(OpRequest::CaStoreCredentials {
        client_id,
        client_secret,
        vault_passphrase,
    })?);
    Ok(())
}

/// Update CA endpoint settings, leaving unspecified fields as they are.
fn ca_configure(
    api_base: Option<String>,
    org_id: Option<String>,
    product_code: Option<String>,
    token_url: Option<String>,
) -> Result<()> {
    if api_base.is_none() && org_id.is_none() && product_code.is_none() && token_url.is_none() {
        anyhow::bail!(
            "Nothing to change. Pass at least one of --api-base, --org-id, --product-code, --token-url."
        );
    }

    // Read-modify-write: the op writes the whole file, so omitted flags must
    // carry the current values forward rather than blanking them.
    let current = ssl_toolbox_ops::run(OpRequest::CaLoadSettings)?;
    let OpOutcome::CaSettingsLoaded(view) = current.outcome else {
        anyhow::bail!("Could not read the current CA settings");
    };

    report(ssl_toolbox_ops::run(OpRequest::CaSaveSettings {
        api_base: api_base.unwrap_or(view.api_base),
        org_id: org_id.unwrap_or(view.org_id),
        product_code: product_code.unwrap_or(view.product_code),
        token_url: token_url.unwrap_or(view.token_url),
    })?);
    Ok(())
}

fn print_validation_audit_feedback(entry: &audit::ValidationAuditEntry) {
    let path = settings::validation_log_path()
        .map(|path| path.to_string_lossy().to_string())
        .unwrap_or_else(|| "~/.ssl-toolbox/validation-log.jsonl".to_string());

    println!(
        "Audit: {} {}:{} at {}",
        entry.kind.title(),
        format_connect_target(&entry.host),
        entry.port,
        entry.timestamp_utc
    );
    println!("Audit Log: {path}");
    if let Some(previous) = &entry.comparison.previous_timestamp_utc {
        println!("Changes Since {previous}:");
    } else {
        println!("Changes:");
    }
    for change in entry.comparison.changes.iter().take(6) {
        println!("  - {change}");
    }
}

/// Prefix a saved report with the audit header so the file is self-describing.
fn render_verify_results_report(
    report: &str,
    audit_entry: Option<&audit::ValidationAuditEntry>,
) -> String {
    let Some(audit_entry) = audit_entry else {
        return report.to_string();
    };

    let mut output = String::new();
    output.push_str("Validation Audit\n");
    output.push_str("================\n");
    output.push_str(&format!("Timestamp (UTC): {}\n", audit_entry.timestamp_utc));
    output.push_str(&format!("Action: {}\n", audit_entry.kind.title()));
    output.push_str(&format!(
        "Endpoint: {}:{}\n",
        audit_entry.host, audit_entry.port
    ));
    output.push_str(&format!(
        "Certificate Validation: {}\n",
        if audit_entry.certificate_validation_requested {
            "Enabled"
        } else {
            "Disabled"
        }
    ));
    output.push_str(&format!(
        "Full Scan: {}\n",
        if audit_entry.full_scan {
            "Enabled"
        } else {
            "Disabled"
        }
    ));
    output.push_str(&format!(
        "Outcome: {}\n",
        match audit_entry.status {
            audit::ValidationAuditStatus::Success => "Success",
            audit::ValidationAuditStatus::Failure => "Failure",
        }
    ));
    if let Some(previous) = &audit_entry.comparison.previous_timestamp_utc {
        output.push_str(&format!("Compared To: {previous}\n"));
    }
    output.push_str("Changes:\n");
    for change in &audit_entry.comparison.changes {
        output.push_str(&format!("- {change}\n"));
    }
    output.push('\n');
    output.push_str(report);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use ssl_toolbox_ops::audit::{
        ValidationAuditEntry, ValidationAuditStatus, ValidationComparison,
    };
    use ssl_toolbox_ops::workflow::ActionKind;

    /// Parity is an architectural contract (ARCHITECTURE.md §10.6): if the
    /// desktop app can store CA credentials and the CLI cannot, the two
    /// front-ends have already drifted. This pins the CLI half of that surface.
    #[test]
    fn the_cli_can_manage_ca_credentials_and_settings() {
        let cli = Cli::try_parse_from(["ssl-toolbox", "ca", "login", "--client-id", "svc-client"])
            .expect("parsed cli");
        match cli.command {
            Commands::Ca(CaCommands::Login { client_id }) => {
                assert_eq!(client_id.as_deref(), Some("svc-client"));
            }
            _ => panic!("unexpected command"),
        }

        // No --client-secret flag exists on purpose: a secret passed as an
        // argument lands in the shell history and in `ps` output. It is
        // prompted for instead.
        assert!(
            Cli::try_parse_from(["ssl-toolbox", "ca", "login", "--client-secret", "s3cret"])
                .is_err(),
            "a client secret must never be accepted as a command-line argument"
        );

        let cli = Cli::try_parse_from([
            "ssl-toolbox",
            "ca",
            "configure",
            "--org-id",
            "12345",
            "--token-url",
            "https://idp.example.test/token",
        ])
        .expect("parsed cli");
        match cli.command {
            Commands::Ca(CaCommands::Configure {
                api_base,
                org_id,
                product_code,
                token_url,
            }) => {
                assert_eq!(org_id.as_deref(), Some("12345"));
                assert_eq!(token_url.as_deref(), Some("https://idp.example.test/token"));
                assert_eq!(api_base, None, "omitted fields must stay unset, not blank");
                assert_eq!(product_code, None);
            }
            _ => panic!("unexpected command"),
        }

        for (args, expected) in [
            (["ca", "logout"], "logout"),
            (["ca", "settings"], "settings"),
            (["ca", "test-connection"], "test-connection"),
        ] {
            Cli::try_parse_from(["ssl-toolbox", args[0], args[1]])
                .unwrap_or_else(|error| panic!("`ca {expected}` must parse: {error}"));
        }
    }

    #[test]
    fn verify_https_accepts_out_flag() {
        let cli = Cli::try_parse_from([
            "ssl-toolbox",
            "verify-https",
            "--host",
            "example.com",
            "--out",
            "report.txt",
        ])
        .expect("parsed cli");

        match cli.command {
            Commands::VerifyHttps {
                host,
                port,
                no_verify,
                full_scan,
                out,
                export_certs,
            } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
                assert!(!no_verify);
                assert!(!full_scan);
                assert_eq!(out.as_deref(), Some("report.txt"));
                assert_eq!(export_certs, None);
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn verify_https_accepts_export_certs_flag() {
        let cli = Cli::try_parse_from([
            "ssl-toolbox",
            "verify-https",
            "--host",
            "example.com",
            "--export-certs",
            "certs",
        ])
        .expect("parsed cli");

        match cli.command {
            Commands::VerifyHttps { export_certs, .. } => {
                assert_eq!(export_certs.as_deref(), Some("certs"));
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn verify_ldaps_accepts_out_flag() {
        let cli = Cli::try_parse_from([
            "ssl-toolbox",
            "verify-ldaps",
            "--host",
            "ldap.example.com",
            "--out",
            "ldaps.txt",
        ])
        .expect("parsed cli");

        match cli.command {
            Commands::VerifyLdaps {
                host,
                port,
                no_verify,
                full_scan,
                ldap_config_test,
                ldap_port,
                ldap_bind_dn,
                ldap_bind_password,
                out,
                export_certs,
            } => {
                assert_eq!(host, "ldap.example.com");
                assert_eq!(port, 636);
                assert!(!no_verify);
                assert!(!full_scan);
                assert!(!ldap_config_test);
                assert_eq!(ldap_port, None);
                assert_eq!(ldap_bind_dn, None);
                assert_eq!(ldap_bind_password, None);
                assert_eq!(out.as_deref(), Some("ldaps.txt"));
                assert_eq!(export_certs, None);
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn verify_ldaps_accepts_export_certs_flag() {
        let cli = Cli::try_parse_from([
            "ssl-toolbox",
            "verify-ldaps",
            "--host",
            "ldap.example.com",
            "--export-certs",
            "ldaps-certs",
        ])
        .expect("parsed cli");

        match cli.command {
            Commands::VerifyLdaps { export_certs, .. } => {
                assert_eq!(export_certs.as_deref(), Some("ldaps-certs"));
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn verify_ldaps_accepts_ldap_config_test_flags() {
        let cli = Cli::try_parse_from([
            "ssl-toolbox",
            "verify-ldaps",
            "--host",
            "ldap.example.com",
            "--ldap-config-test",
            "--ldap-port",
            "1389",
        ])
        .expect("parsed cli");

        match cli.command {
            Commands::VerifyLdaps {
                host,
                ldap_config_test,
                ldap_port,
                ..
            } => {
                assert_eq!(host, "ldap.example.com");
                assert!(ldap_config_test);
                assert_eq!(ldap_port, Some(1389));
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn verify_ldaps_accepts_authenticated_ldap_config_test_flags() {
        let cli = Cli::try_parse_from([
            "ssl-toolbox",
            "verify-ldaps",
            "--host",
            "ldap.example.com",
            "--ldap-config-test",
            "--ldap-bind-dn",
            "cn=reader,dc=example,dc=com",
            "--ldap-bind-password",
            "secret",
        ])
        .expect("parsed cli");

        match cli.command {
            Commands::VerifyLdaps {
                ldap_config_test,
                ldap_bind_dn,
                ldap_bind_password,
                ..
            } => {
                assert!(ldap_config_test);
                assert_eq!(ldap_bind_dn.as_deref(), Some("cn=reader,dc=example,dc=com"));
                assert_eq!(ldap_bind_password.as_deref(), Some("secret"));
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn verify_smtp_accepts_out_flag() {
        let cli = Cli::try_parse_from([
            "ssl-toolbox",
            "verify-smtp",
            "--host",
            "smtp.example.com",
            "--out",
            "smtp.txt",
        ])
        .expect("parsed cli");

        match cli.command {
            Commands::VerifySmtp {
                host,
                port,
                no_verify,
                out,
            } => {
                assert_eq!(host, "smtp.example.com");
                assert_eq!(port, 587);
                assert!(!no_verify);
                assert_eq!(out.as_deref(), Some("smtp.txt"));
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn running_with_no_subcommand_shows_help_instead_of_launching_a_menu() {
        // Bare `ssl-toolbox` used to launch the interactive menu. It must now
        // show the user what the CLI can do rather than silently doing nothing.
        let error = Cli::try_parse_from(["ssl-toolbox"])
            .err()
            .expect("a subcommand is required");

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand,
            "bare invocation should display help, got: {error}"
        );

        let rendered = error.to_string();
        assert!(
            rendered.contains("Usage: ssl-toolbox"),
            "help output should show usage, got: {rendered}"
        );
        assert!(
            rendered.contains("verify-https"),
            "help output should list the available commands, got: {rendered}"
        );
    }

    #[test]
    fn render_verify_results_report_adds_timestamped_audit_header() {
        let audit_entry = ValidationAuditEntry {
            timestamp_secs: 1_704_067_200,
            timestamp_utc: "2024-01-01T00:00:00Z".to_string(),
            kind: ActionKind::VerifyLdaps,
            host: "ldap.example.com".to_string(),
            port: 636,
            certificate_validation_requested: true,
            full_scan: true,
            status: ValidationAuditStatus::Success,
            result: None,
            error: None,
            comparison: ValidationComparison {
                previous_timestamp_utc: Some("2023-12-31T00:00:00Z".to_string()),
                changes: vec!["Leaf certificate SHA256 fingerprint changed.".to_string()],
            },
        };

        let rendered = render_verify_results_report("raw report body", Some(&audit_entry));

        assert!(rendered.contains("Timestamp (UTC): 2024-01-01T00:00:00Z"));
        assert!(rendered.contains("Action: Verify LDAPS Endpoint"));
        assert!(rendered.contains("Compared To: 2023-12-31T00:00:00Z"));
        assert!(rendered.contains("- Leaf certificate SHA256 fingerprint changed."));
        assert!(rendered.ends_with("raw report body"));
    }
}

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
use ssl_toolbox_ops::{audit, settings};

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
    },
    /// View details of a CSR
    ViewCsr {
        #[arg(short, long)]
        input: String,
    },
    /// View contents of a PFX/PKCS12 file
    ViewPfx {
        #[arg(short, long)]
        input: String,
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
    ListProfiles,
    /// Submit CSR to CA for signing
    Submit {
        #[arg(short, long)]
        csr: String,
        #[arg(short, long)]
        out: String,
        #[arg(short, long)]
        description: Option<String>,
        #[arg(short, long)]
        product_code: Option<String>,
    },
    /// Collect/download a signed certificate by request ID
    Collect {
        #[arg(short, long)]
        id: String,
        #[arg(short, long)]
        out: String,
        /// Format: pem, chain, pkcs7
        #[arg(short, long, default_value = "pem")]
        format: String,
    },
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

        Commands::Identify { input } => {
            report(ssl_toolbox_ops::run(OpRequest::IdentifyFormat { input })?);
        }

        Commands::ViewConfig { input } => {
            report(ssl_toolbox_ops::run(OpRequest::LoadConfig { path: input })?);
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

        Commands::ViewCert { input } => {
            report(ssl_toolbox_ops::run(OpRequest::InspectCert { input })?);
        }

        Commands::ViewCsr { input } => {
            report(ssl_toolbox_ops::run(OpRequest::InspectCsr { input })?);
        }

        Commands::ViewPfx { input } => {
            let password = prompt_new_password("Enter PFX password")?;
            report(ssl_toolbox_ops::run(OpRequest::InspectPfx {
                input,
                password,
            })?);
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

/// Render the outcome of a non-verification operation.
fn report(result: OpResult) {
    match result.outcome {
        OpOutcome::KeyCreated { path } => println!("Success: Generated {path}"),
        OpOutcome::CsrGenerated {
            csr_path,
            key_path,
            key_created,
            ..
        } => {
            if key_created {
                println!("Success: Generated {key_path} and {csr_path}");
            } else {
                println!("Success: Generated {csr_path}");
            }
        }
        OpOutcome::PfxCreated { path, legacy } => {
            if legacy {
                println!("Success: Legacy PFX (TripleDES-SHA1) created at {path}");
            } else {
                println!("Success: PFX created at {path}");
            }
        }
        OpOutcome::ConfigWritten { path } => {
            println!("Success: OpenSSL config written to {path}")
        }
        OpOutcome::ConfigLoaded {
            path,
            text,
            summary,
        } => {
            println!("{text}");
            print!("{}", display::render_config_summary(&summary, &path));
        }
        OpOutcome::ConfigSaved {
            path,
            backup,
            summary,
        } => {
            if let Some(backup) = &backup {
                println!("Previous contents saved to {backup}");
            }
            println!("Success: OpenSSL config written to {path}");
            print!("{}", display::render_config_summary(&summary, &path));
        }
        OpOutcome::CertInspected { chain, .. } => {
            display::display_cert_details_list(&chain, "Certificate Details")
        }
        OpOutcome::CsrInspected {
            common_name, sans, ..
        } => {
            println!("\n╔═══════════════════════════════════════════════════════════════╗");
            println!("║                        CSR Details                           ║");
            println!("╚═══════════════════════════════════════════════════════════════╝\n");
            println!("  CommonName: {common_name}");
            if sans.is_empty() {
                println!("  SANs: None");
            } else {
                println!("  SANs:");
                for san in &sans {
                    println!("    • {san}");
                }
            }
            println!();
        }
        OpOutcome::PfxInspected { details, .. } => {
            display::display_pfx_details(&details, "PFX Contents")
        }
        OpOutcome::FormatConverted { output, format } => {
            println!("Success: Converted to {format}: {output}")
        }
        OpOutcome::FormatIdentified {
            path, description, ..
        } => {
            println!("File: {path}");
            println!("Format: {description}");
        }
        OpOutcome::CaProfilesListed { provider, profiles } => {
            println!("\nAvailable certificate profiles from {provider}:\n");
            for profile in &profiles {
                println!("  [{}] {}", profile.id, profile.name);
                if let Some(description) = &profile.description {
                    println!("      {description}");
                }
                if !profile.terms.is_empty() {
                    println!("      Terms (days): {:?}", profile.terms);
                }
            }
            println!();
        }
        OpOutcome::CaCsrSubmitted { request_id, path } => {
            println!("Success: CSR submitted. Request ID {request_id} saved to {path}")
        }
        OpOutcome::CaCertCollected { path, .. } => {
            println!("Success: Certificate collected to {path}")
        }
        OpOutcome::EndpointVerified(_) => {
            unreachable!("endpoint verification is rendered by `verify`")
        }
    }
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
    let request = match cmd {
        CaCommands::ListProfiles => OpRequest::CaListProfiles { debug },
        CaCommands::Submit {
            csr,
            out,
            description,
            product_code,
        } => OpRequest::CaSubmitCsr {
            csr,
            out,
            description,
            product_code,
            term_days: None,
            debug,
        },
        CaCommands::Collect { id, out, format } => OpRequest::CaCollectCert {
            request_id: id,
            out,
            format,
            debug,
        },
    };

    report(ssl_toolbox_ops::run(request)?);
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

mod display;
mod settings;
mod workflow;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use cliclack::{clear_screen, confirm, input, intro, outro, password, select};
use crossterm::{
    style::{Color, Stylize},
    terminal,
};
use dotenvy::dotenv;
use std::borrow::Cow;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use ssl_toolbox_core::{ConfigInputs, CsrDefaults};
use workflow::{
    ActionKind, ArtifactKind, JobRecord, PaletteEntry, WorkflowProfile, WorkspaceSnapshot,
    apply_job_to_workflow, build_preview, builtin_profiles, next_steps, path_suggestions,
    profile_by_id, push_recent_job, search_palette, suggest_output_path, validation_steps,
};

#[derive(Parser)]
#[command(name = "ssl-toolbox", author, version, about = "SSL/TLS Security Toolbox", long_about = None)]
struct Cli {
    /// Enable debug output
    #[arg(long, global = true)]
    debug: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate key and CSR from config
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
        /// Save results to a file
        #[arg(short, long)]
        out: Option<String>,
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

    match cli.command {
        Some(cmd) => execute_command(cmd, cli.debug),
        None => run_interactive_menu(cli.debug),
    }
}

#[cfg(feature = "sectigo")]
fn get_ca_plugin(debug: bool) -> Result<Box<dyn ssl_toolbox_ca::CaPlugin>> {
    let sectigo_config: ssl_toolbox_ca_sectigo::SectigoConfig = settings::load_ca_config("sectigo");
    ssl_toolbox_ca_sectigo::SectigoPlugin::configure_with_config(&sectigo_config, debug)
}

#[cfg(not(feature = "sectigo"))]
fn get_ca_plugin(_debug: bool) -> Result<Box<dyn ssl_toolbox_ca::CaPlugin>> {
    Err(anyhow::anyhow!(
        "No CA plugin compiled. Build with --features sectigo"
    ))
}

fn execute_command(cmd: Commands, debug: bool) -> Result<()> {
    match cmd {
        Commands::Generate {
            conf,
            key,
            csr,
            password: pw,
        } => {
            let pass = if let Some(p) = pw {
                p
            } else {
                password("Enter password for private key").interact()?
            };
            ssl_toolbox_core::key_csr::generate_key_and_csr(&conf, &key, &csr, &pass)?;
            println!("Success: Generated {} and {}", key, csr);
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
            let key_pass: String =
                password("Enter password for private key (or press Enter if not encrypted)")
                    .allow_empty()
                    .interact()?;
            let key_pass_opt = if key_pass.is_empty() {
                None
            } else {
                Some(key_pass.as_str())
            };

            let pfx_pass: String = password("Enter password for PFX export").interact()?;

            if legacy {
                ssl_toolbox_core::pfx::create_pfx_legacy(
                    &key,
                    &cert,
                    chain.as_deref(),
                    &out,
                    key_pass_opt,
                    &pfx_pass,
                )?;
                println!("Success: Legacy PFX (TripleDES-SHA1) created at {}", out);
            } else {
                ssl_toolbox_core::pfx::create_pfx(
                    &key,
                    &cert,
                    chain.as_deref(),
                    &out,
                    key_pass_opt,
                    &pfx_pass,
                )?;
                println!("Success: PFX created at {}", out);
            }
        }
        Commands::PfxLegacy { input, out } => {
            let input_pass: String = password("Enter password for input PFX").interact()?;
            let output_pass: String = password("Enter password for output PFX").interact()?;
            let pfx_bytes = std::fs::read(&input)?;
            ssl_toolbox_core::pfx::create_pfx_legacy_3des(
                &pfx_bytes,
                &input_pass,
                &out,
                &output_pass,
            )?;
            println!("Success: Legacy PFX (TripleDES-SHA1) created at {}", out);
        }
        Commands::Convert {
            input,
            output,
            format,
        } => match format.to_lowercase().as_str() {
            "der" => {
                ssl_toolbox_core::convert::pem_to_der(&input, &output)?;
                println!("Success: Converted PEM to DER: {}", output);
            }
            "pem" => {
                ssl_toolbox_core::convert::der_to_pem(&input, &output)?;
                println!("Success: Converted DER to PEM: {}", output);
            }
            "base64" => {
                ssl_toolbox_core::convert::pem_to_base64(&input, &output)?;
                println!("Success: Converted PEM to Base64: {}", output);
            }
            other => {
                return Err(anyhow::anyhow!(
                    "Unsupported format: '{}'. Use: pem, der, base64",
                    other
                ));
            }
        },
        Commands::Identify { input } => {
            let data = std::fs::read(&input)?;
            let format = ssl_toolbox_core::convert::detect_format(&data);
            let desc = ssl_toolbox_core::convert::format_description(format);
            println!("File: {}", input);
            println!("Format: {}", desc);
        }
        Commands::NewConfig { out } => {
            let app_config = settings::load_config();
            let inputs = prompt_config_inputs(&app_config.csr_defaults, None)?;
            let output_path = if let Some(o) = out {
                o
            } else {
                let default_path = format!("{}.cnf", inputs.common_name);
                let path: String = input("Output .cnf file path")
                    .default_input(&default_path)
                    .interact()?;
                path
            };
            print_config_summary(&inputs, &output_path);
            let confirmed: bool = confirm("Write this config file?").interact()?;
            if confirmed {
                ssl_toolbox_core::config::generate_conf_from_inputs(&inputs, &output_path)?;
                println!("Success: OpenSSL config written to {}", output_path);
            } else {
                println!("Cancelled.");
            }
        }
        Commands::Config {
            input: input_path,
            out,
            is_csr,
        } => {
            ssl_toolbox_core::config::generate_conf_from_cert_or_csr(&input_path, &out, is_csr)?;
            println!("Success: OpenSSL config written to {}", out);
        }
        Commands::ViewCert { input } => {
            let cert_content = std::fs::read(&input)?;
            display::display_cert_chain(&cert_content, "Certificate Details");
        }
        Commands::ViewCsr { input } => {
            println!("\n╔═══════════════════════════════════════════════════════════════╗");
            println!("║                        CSR Details                           ║");
            println!("╚═══════════════════════════════════════════════════════════════╝\n");

            match ssl_toolbox_core::key_csr::extract_csr_details(&input) {
                Ok((cn, sans)) => {
                    println!("  CommonName: {}", cn);
                    if sans.is_empty() {
                        println!("  SANs: None");
                    } else {
                        println!("  SANs:");
                        for san in &sans {
                            println!("    • {}", san);
                        }
                    }
                    println!();
                }
                Err(e) => {
                    eprintln!("Error: Could not extract CSR details: {}", e);
                }
            }
        }
        Commands::ViewPfx { input } => {
            let pfx_bytes = std::fs::read(&input)?;
            let pfx_pass: String = password("Enter PFX password").interact()?;
            match ssl_toolbox_core::pfx::extract_pfx_bundle_details(&pfx_bytes, &pfx_pass) {
                Ok(details) => {
                    display::display_pfx_details(&details, "PFX Contents");
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                }
            }
        }
        Commands::VerifyHttps {
            host,
            port,
            no_verify,
            full_scan,
            out,
        } => {
            let (host, port) = normalize_tls_endpoint_target(&host, port, 443)?;
            println!(
                "\nConnecting to {}:{}...",
                format_connect_target(&host),
                port
            );
            let verify = !no_verify;
            match ssl_toolbox_core::tls::connect_and_check(&host, port, verify, full_scan) {
                Ok(result) => {
                    let report =
                        display::render_tls_check_result(&result, "HTTPS Endpoint Verification");
                    print!("{report}");
                    if let Some(path) = out.as_deref() {
                        write_verify_results(path, &report)?;
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                }
            }
        }
        Commands::VerifyLdaps {
            host,
            port,
            no_verify,
            full_scan,
            out,
        } => {
            let (host, port) = normalize_tls_endpoint_target(&host, port, 636)?;
            println!(
                "\nConnecting to {}:{}...",
                format_connect_target(&host),
                port
            );
            let verify = !no_verify;
            match ssl_toolbox_core::tls::connect_and_check(&host, port, verify, full_scan) {
                Ok(result) => {
                    let report =
                        display::render_tls_check_result(&result, "LDAPS Endpoint Verification");
                    print!("{report}");
                    if let Some(path) = out.as_deref() {
                        write_verify_results(path, &report)?;
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                }
            }
        }
        Commands::VerifySmtp {
            host,
            port,
            no_verify,
            out,
        } => {
            println!("\nConnecting to {}:{}...", host, port);
            let verify = !no_verify;
            match ssl_toolbox_core::smtp::connect_and_check_smtp(&host, port, verify) {
                Ok(result) => {
                    let report = display::render_tls_check_result(
                        &result,
                        "SMTP STARTTLS Endpoint Verification",
                    );
                    print!("{report}");
                    if let Some(path) = out.as_deref() {
                        write_verify_results(path, &report)?;
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                }
            }
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
        Commands::Ca(ca_cmd) => {
            let plugin = get_ca_plugin(debug)?;
            execute_ca_command(ca_cmd, plugin, debug)?;
        }
    }
    Ok(())
}

fn execute_ca_command(
    cmd: CaCommands,
    plugin: Box<dyn ssl_toolbox_ca::CaPlugin>,
    debug: bool,
) -> Result<()> {
    match cmd {
        CaCommands::ListProfiles => {
            let profiles = plugin.list_profiles(debug)?;
            if profiles.is_empty() {
                println!("\nNo SSL profiles available.");
            } else {
                println!("\n╔═══════════════════════════════════════════════════════════════╗");
                println!("║              Available SSL Certificate Types                 ║");
                println!("╚═══════════════════════════════════════════════════════════════╝\n");

                for profile in profiles {
                    println!("  • {} (ID: {})", profile.name, profile.id);
                    if !profile.terms.is_empty() {
                        let terms: Vec<String> = profile
                            .terms
                            .iter()
                            .map(|t| format!("{} days", t))
                            .collect();
                        println!("    Available terms: {}", terms.join(", "));
                    }
                    println!();
                }
            }
        }
        CaCommands::Submit {
            csr,
            out,
            description,
            product_code,
        } => {
            let csr_content = std::fs::read_to_string(&csr)?;

            // Show CSR details before submitting
            println!("\n╔═══════════════════════════════════════════════════════════════╗");
            println!("║                    CSR Details Review                        ║");
            println!("╚═══════════════════════════════════════════════════════════════╝\n");

            if let Ok((cn, sans)) = ssl_toolbox_core::key_csr::extract_csr_details(&csr) {
                println!("  CommonName: {}", cn);
                if sans.is_empty() {
                    println!("  SANs: None");
                } else {
                    println!("  SANs:");
                    for san in &sans {
                        println!("    • {}", san);
                    }
                }
                println!();
            }

            let options = ssl_toolbox_ca::SubmitOptions {
                description,
                product_code,
                term_days: None,
            };

            let request_id = plugin.submit_csr(&csr_content, &options, debug)?;
            println!("Certificate submitted. Request ID: {}", request_id);

            println!("Waiting 20 seconds for certificate to be processed...");
            std::thread::sleep(std::time::Duration::from_secs(20));

            println!("Downloading certificate (PEM format)...");
            let cert_content =
                plugin.collect_cert(&request_id, ssl_toolbox_ca::CollectFormat::PemCert, debug)?;
            std::fs::write(&out, &cert_content)?;

            display::display_cert_chain(cert_content.as_bytes(), "Downloaded Certificate Details");
            println!("Success: Certificate saved to {}", out);
        }
        CaCommands::Collect { id, out, format } => {
            let collect_format = match format.to_lowercase().as_str() {
                "pem" => ssl_toolbox_ca::CollectFormat::PemCert,
                "chain" => ssl_toolbox_ca::CollectFormat::PemChain,
                "pkcs7" => ssl_toolbox_ca::CollectFormat::Pkcs7,
                other => {
                    return Err(anyhow::anyhow!(
                        "Unsupported format: '{}'. Use: pem, chain, pkcs7",
                        other
                    ));
                }
            };

            let cert_content = plugin.collect_cert(&id, collect_format, debug)?;
            std::fs::write(&out, &cert_content)?;
            println!("Success: Certificate saved to {}", out);
        }
    }
    Ok(())
}

fn pause_for_menu_return() -> Result<()> {
    println!();
    print!("{}", "Press Enter to return to the menu...".dark_grey());
    io::stdout().flush()?;

    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    clear_screen()?;
    Ok(())
}

fn run_interactive_menu(debug: bool) -> Result<()> {
    #[cfg(not(feature = "sectigo"))]
    let _ = debug;

    let mut app_config = settings::load_config();

    intro("SSL/TLS Security Toolbox")?;

    loop {
        let workspace = current_workspace_snapshot();
        merge_detected_workflow(
            &mut app_config.ui_state.workflow,
            &workspace.detect_workflow(),
        );
        let menu = build_main_menu();
        print_dashboard(&app_config.ui_state, &workspace);
        print_main_menu(&menu);
        let selection = prompt_main_menu_choice(&menu, &mut app_config.ui_state)?;
        let mut should_pause = false;

        match selection {
            -1 => continue,
            -2 => {
                replay_recent_job(&mut app_config.ui_state, debug, false)?;
                should_pause = true;
            }
            -3 => {
                replay_recent_job(&mut app_config.ui_state, debug, true)?;
                should_pause = true;
            }
            -4 => {
                clear_screen()?;
                print_recent_jobs(&app_config.ui_state);
                should_pause = true;
            }
            -5 => {
                clear_screen()?;
                print_workspace_overview(&workspace);
                should_pause = true;
            }
            -6 => {
                select_active_profile(&mut app_config.ui_state)?;
            }
            0 => {
                let conf = prompt_path(
                    &mut app_config.ui_state,
                    "generate.conf",
                    "Path to openssl.conf",
                    None,
                )?;
                let default_key = derive_path(&conf, "key");
                let default_csr = derive_path(&conf, "csr");

                let key = prompt_path(
                    &mut app_config.ui_state,
                    "generate.key",
                    "Path to output .key file",
                    non_empty(default_key),
                )?;
                let csr = prompt_path(
                    &mut app_config.ui_state,
                    "generate.csr",
                    "Path to output .csr file",
                    non_empty(default_csr),
                )?;

                let job = build_generate_job(
                    &conf,
                    &key,
                    &csr,
                    app_config.ui_state.workflow.active_profile.as_deref(),
                );
                show_preview_and_confirm(&job)?;

                let pass: String = password("Enter password for private key").interact()?;
                ssl_toolbox_core::key_csr::generate_key_and_csr(&conf, &key, &csr, &pass)?;
                clear_screen()?;
                println!(
                    "Success: Generated {} and {}",
                    display_path(&key),
                    display_path(&csr)
                );
                finalize_job(&mut app_config.ui_state, job);
                should_pause = true;
            }
            1 => {
                let key = prompt_path(
                    &mut app_config.ui_state,
                    "pfx.key",
                    "Path to .key file",
                    None,
                )?;
                let default_cert = derive_path(&key, "crt");
                let default_pfx = derive_path(&key, "pfx");

                let cert = prompt_path(
                    &mut app_config.ui_state,
                    "pfx.cert",
                    "Path to signed .crt file",
                    non_empty(default_cert),
                )?;
                let chain = prompt_optional_path(
                    &mut app_config.ui_state,
                    "pfx.chain",
                    "Path to chain file (optional)",
                    None,
                )?;
                let out = prompt_path(
                    &mut app_config.ui_state,
                    "pfx.output",
                    "Path to output .pfx file",
                    non_empty(default_pfx),
                )?;

                let use_legacy: bool = confirm("Use legacy TripleDES-SHA1 encryption?")
                    .initial_value(false)
                    .interact()?;

                println!(
                    "Note: If your private key is encrypted, you'll be prompted for its password."
                );
                println!("If not encrypted, just press Enter when prompted.");
                let key_pass: String =
                    password("Enter password for private key (or press Enter if not encrypted)")
                        .allow_empty()
                        .interact()?;
                let key_pass_opt = if key_pass.is_empty() {
                    None
                } else {
                    Some(key_pass.as_str())
                };

                let pfx_pass: String = password("Enter password for PFX export").interact()?;
                let chain_opt = chain.as_deref();

                let mut job = JobRecord::new(
                    if use_legacy {
                        ActionKind::CreateLegacyPfx
                    } else {
                        ActionKind::CreatePfx
                    },
                    format!(
                        "Create {} from {}",
                        if use_legacy { "legacy PFX" } else { "PFX" },
                        display_path(&cert)
                    ),
                )
                .with_input("key", key.clone())
                .with_input("cert", cert.clone())
                .with_output(if use_legacy { "legacy_pfx" } else { "pfx" }, out.clone());
                if let Some(chain) = &chain {
                    job.inputs.insert("chain".to_string(), chain.clone());
                }
                show_preview_and_confirm(&job)?;

                if use_legacy {
                    ssl_toolbox_core::pfx::create_pfx_legacy(
                        &key,
                        &cert,
                        chain_opt,
                        &out,
                        key_pass_opt,
                        &pfx_pass,
                    )?;
                    clear_screen()?;
                    println!("Success: Legacy PFX created at {}", display_path(&out));
                } else {
                    ssl_toolbox_core::pfx::create_pfx(
                        &key,
                        &cert,
                        chain_opt,
                        &out,
                        key_pass_opt,
                        &pfx_pass,
                    )?;
                    clear_screen()?;
                    println!("Success: PFX created at {}", display_path(&out));
                }
                finalize_job(&mut app_config.ui_state, job);
                should_pause = true;
            }
            2 => {
                let input_path = prompt_path(
                    &mut app_config.ui_state,
                    "pfx_legacy.input",
                    "Path to existing PFX file",
                    None,
                )?;
                let default_out = derive_path(&input_path, "legacy.pfx");
                let out = prompt_path(
                    &mut app_config.ui_state,
                    "pfx_legacy.output",
                    "Path to output legacy PFX file",
                    non_empty(default_out),
                )?;

                let job = JobRecord::new(
                    ActionKind::CreateLegacyPfx,
                    format!("Convert {} to legacy PFX", display_path(&input_path)),
                )
                .with_input("pfx", input_path.clone())
                .with_output("legacy_pfx", out.clone());
                show_preview_and_confirm(&job)?;

                let input_pass: String = password("Enter password for input PFX").interact()?;
                let output_pass: String = password("Enter password for output PFX").interact()?;

                let pfx_bytes = std::fs::read(&input_path)?;
                ssl_toolbox_core::pfx::create_pfx_legacy_3des(
                    &pfx_bytes,
                    &input_pass,
                    &out,
                    &output_pass,
                )?;
                clear_screen()?;
                println!(
                    "Success: Legacy PFX (TripleDES-SHA1) created at {}",
                    display_path(&out)
                );
                finalize_job(&mut app_config.ui_state, job);
                should_pause = true;
            }
            3 => {
                let inputs = prompt_config_inputs(
                    &effective_csr_defaults(&app_config.ui_state, &app_config.csr_defaults),
                    active_profile(&app_config.ui_state),
                )?;
                let default_path = format!("{}.cnf", inputs.common_name);
                let output_path = prompt_path(
                    &mut app_config.ui_state,
                    "new_config.output",
                    "Output .cnf file path",
                    Some(default_path),
                )?;
                print_config_summary(&inputs, &output_path);
                let job = build_new_config_job(
                    &output_path,
                    app_config.ui_state.workflow.active_profile.as_deref(),
                    Some(&inputs),
                );
                show_preview_and_confirm(&job)?;
                ssl_toolbox_core::config::generate_conf_from_inputs(&inputs, &output_path)?;
                clear_screen()?;
                println!(
                    "Success: OpenSSL config written to {}",
                    display_path(&output_path)
                );
                finalize_job(&mut app_config.ui_state, job);
                should_pause = true;
            }
            4 => {
                let input_path = prompt_path(
                    &mut app_config.ui_state,
                    "config_from_existing.input",
                    "Path to existing .cer or .csr",
                    None,
                )?;
                let out = prompt_path(
                    &mut app_config.ui_state,
                    "config_from_existing.output",
                    "Path to output .conf file",
                    non_empty(derive_path(&input_path, "conf")),
                )?;
                let job = JobRecord::new(
                    ActionKind::ConfigFromExisting,
                    format!("Generate config from {}", display_path(&input_path)),
                )
                .with_input("source", input_path.clone())
                .with_output("config", out.clone());
                show_preview_and_confirm(&job)?;
                let is_csr = input_path.ends_with(".csr");
                ssl_toolbox_core::config::generate_conf_from_cert_or_csr(
                    &input_path,
                    &out,
                    is_csr,
                )?;
                clear_screen()?;
                println!("Success: OpenSSL config written to {}", display_path(&out));
                finalize_job(&mut app_config.ui_state, job);
                should_pause = true;
            }
            5 => {
                let input_path = prompt_path(
                    &mut app_config.ui_state,
                    "view_cert.input",
                    "Path to certificate file (.crt, .cer, .pem)",
                    None,
                )?;
                clear_screen()?;
                let success = match std::fs::read(&input_path) {
                    Ok(cert_content) => {
                        display::display_cert_chain(&cert_content, "Certificate Details");
                        true
                    }
                    Err(e) => {
                        eprintln!("Error reading file: {}", e);
                        false
                    }
                };
                finalize_job_if_success(
                    &mut app_config.ui_state,
                    JobRecord::new(
                        ActionKind::ViewCert,
                        format!("Inspect certificate {}", display_path(&input_path)),
                    )
                    .with_input("cert", input_path),
                    success,
                );
                should_pause = true;
            }
            6 => {
                let input_path = prompt_path(
                    &mut app_config.ui_state,
                    "view_csr.input",
                    "Path to CSR file (.csr)",
                    None,
                )?;
                clear_screen()?;
                println!("\n╔═══════════════════════════════════════════════════════════════╗");
                println!("║                        CSR Details                           ║");
                println!("╚═══════════════════════════════════════════════════════════════╝\n");
                let success = match ssl_toolbox_core::key_csr::extract_csr_details(&input_path) {
                    Ok((cn, sans)) => {
                        println!("  CommonName: {}", cn);
                        if sans.is_empty() {
                            println!("  SANs: None");
                        } else {
                            println!("  SANs:");
                            for san in &sans {
                                println!("    • {}", san);
                            }
                        }
                        println!();
                        true
                    }
                    Err(e) => {
                        eprintln!("Error: Could not extract CSR details: {}", e);
                        false
                    }
                };
                finalize_job_if_success(
                    &mut app_config.ui_state,
                    JobRecord::new(
                        ActionKind::ViewCsr,
                        format!("Inspect CSR {}", display_path(&input_path)),
                    )
                    .with_input("csr", input_path),
                    success,
                );
                should_pause = true;
            }
            7 => {
                let input_path = prompt_path(
                    &mut app_config.ui_state,
                    "view_pfx.input",
                    "Path to PFX file (.pfx, .p12)",
                    None,
                )?;
                let pfx_pass: String = password("Enter PFX password").interact()?;
                clear_screen()?;
                let success = match std::fs::read(&input_path) {
                    Ok(pfx_bytes) => {
                        match ssl_toolbox_core::pfx::extract_pfx_bundle_details(
                            &pfx_bytes, &pfx_pass,
                        ) {
                            Ok(details) => {
                                display::display_pfx_details(&details, "PFX Contents");
                                true
                            }
                            Err(e) => {
                                eprintln!("Error: {}", e);
                                false
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading file: {}", e);
                        false
                    }
                };
                finalize_job_if_success(
                    &mut app_config.ui_state,
                    JobRecord::new(
                        ActionKind::ViewPfx,
                        format!("Inspect PFX {}", display_path(&input_path)),
                    )
                    .with_input("pfx", input_path),
                    success,
                );
                should_pause = true;
            }
            8 => {
                let raw_host: String = input("Hostname (e.g. example.com)").interact()?;
                let port_str: String = input("Port").default_input("443").interact()?;
                let requested_port: u16 = port_str.parse().unwrap_or(443);
                let (host, port) = normalize_tls_endpoint_target(&raw_host, requested_port, 443)?;
                let verify: bool = confirm("Validate certificate?")
                    .initial_value(true)
                    .interact()?;
                let full_scan: bool = confirm("Scan all supported protocol/cipher suites?")
                    .initial_value(false)
                    .interact()?;

                clear_screen()?;
                println!(
                    "\nConnecting to {}:{}...",
                    format_connect_target(&host),
                    port
                );
                let success = match ssl_toolbox_core::tls::connect_and_check(
                    &host, port, verify, full_scan,
                ) {
                    Ok(result) => {
                        display::display_tls_check_result(&result, "HTTPS Endpoint Verification");
                        true
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        false
                    }
                };
                finalize_job_if_success(
                    &mut app_config.ui_state,
                    JobRecord::new(
                        ActionKind::VerifyHttps,
                        format!("Verify HTTPS endpoint {host}:{port}"),
                    )
                    .with_input("https_host", host)
                    .with_input("port", port.to_string())
                    .with_input("full_scan", full_scan.to_string()),
                    success,
                );
                should_pause = true;
            }
            9 => {
                let raw_host: String = input("Hostname (e.g. ldap.example.com)").interact()?;
                let port_str: String = input("Port").default_input("636").interact()?;
                let requested_port: u16 = port_str.parse().unwrap_or(636);
                let (host, port) = normalize_tls_endpoint_target(&raw_host, requested_port, 636)?;
                let verify: bool = confirm("Validate certificate?")
                    .initial_value(true)
                    .interact()?;
                let full_scan: bool = confirm("Scan all supported protocol/cipher suites?")
                    .initial_value(false)
                    .interact()?;

                clear_screen()?;
                println!(
                    "\nConnecting to {}:{}...",
                    format_connect_target(&host),
                    port
                );
                let success = match ssl_toolbox_core::tls::connect_and_check(
                    &host, port, verify, full_scan,
                ) {
                    Ok(result) => {
                        display::display_tls_check_result(&result, "LDAPS Endpoint Verification");
                        true
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        false
                    }
                };
                finalize_job_if_success(
                    &mut app_config.ui_state,
                    JobRecord::new(
                        ActionKind::VerifyLdaps,
                        format!("Verify LDAPS endpoint {host}:{port}"),
                    )
                    .with_input("ldaps_host", host)
                    .with_input("port", port.to_string())
                    .with_input("full_scan", full_scan.to_string()),
                    success,
                );
                should_pause = true;
            }
            10 => {
                let host: String = input("SMTP hostname (e.g. smtp.gmail.com)").interact()?;
                let port_str: String = input("Port").default_input("587").interact()?;
                let port: u16 = port_str.parse().unwrap_or(587);
                let verify: bool = confirm("Validate certificate?")
                    .initial_value(true)
                    .interact()?;

                clear_screen()?;
                println!("\nConnecting to {}:{}...", host, port);
                let success =
                    match ssl_toolbox_core::smtp::connect_and_check_smtp(&host, port, verify) {
                        Ok(result) => {
                            display::display_tls_check_result(
                                &result,
                                "SMTP STARTTLS Endpoint Verification",
                            );
                            true
                        }
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            false
                        }
                    };
                finalize_job_if_success(
                    &mut app_config.ui_state,
                    JobRecord::new(
                        ActionKind::VerifySmtp,
                        format!("Verify SMTP endpoint {host}:{port}"),
                    )
                    .with_input("smtp_host", host)
                    .with_input("port", port.to_string()),
                    success,
                );
                should_pause = true;
            }
            11 => {
                let format: String = select("Target format")
                    .item("der".to_string(), "DER", "Binary ASN.1 encoding")
                    .item("pem".to_string(), "PEM", "Base64 with headers")
                    .item(
                        "base64".to_string(),
                        "Base64",
                        "Raw base64 (no PEM headers)",
                    )
                    .interact()?;
                let input_path = prompt_path(
                    &mut app_config.ui_state,
                    "convert.input",
                    "Path to certificate file",
                    None,
                )?;
                let output_path = prompt_path(
                    &mut app_config.ui_state,
                    "convert.output",
                    "Path to output file",
                    convert_output_suggestion(&input_path, &format),
                )?;

                let job = JobRecord::new(
                    ActionKind::Convert,
                    format!(
                        "Convert {} to {}",
                        display_path(&input_path),
                        format.to_uppercase()
                    ),
                )
                .with_input("input", input_path.clone())
                .with_output("output", output_path.clone())
                .with_replay_data("format", format.clone());
                show_preview_and_confirm(&job)?;

                match format.as_str() {
                    "der" => {
                        ssl_toolbox_core::convert::pem_to_der(&input_path, &output_path)?;
                        clear_screen()?;
                        println!("Success: Converted to DER: {}", display_path(&output_path));
                    }
                    "pem" => {
                        ssl_toolbox_core::convert::der_to_pem(&input_path, &output_path)?;
                        clear_screen()?;
                        println!("Success: Converted to PEM: {}", display_path(&output_path));
                    }
                    "base64" => {
                        ssl_toolbox_core::convert::pem_to_base64(&input_path, &output_path)?;
                        clear_screen()?;
                        println!(
                            "Success: Converted to Base64: {}",
                            display_path(&output_path)
                        );
                    }
                    _ => unreachable!(),
                }
                finalize_job(&mut app_config.ui_state, job);
                should_pause = true;
            }
            12 => {
                let input_path = prompt_path(
                    &mut app_config.ui_state,
                    "identify.input",
                    "Path to certificate file",
                    None,
                )?;
                let data = std::fs::read(&input_path)?;
                let format = ssl_toolbox_core::convert::detect_format(&data);
                let desc = ssl_toolbox_core::convert::format_description(format);
                clear_screen()?;
                println!("\nFile: {}", display_path(&input_path));
                println!("Format: {}", desc);
                finalize_job(
                    &mut app_config.ui_state,
                    JobRecord::new(
                        ActionKind::Identify,
                        format!("Identify artifact {}", display_path(&input_path)),
                    )
                    .with_input("input", input_path),
                );
                should_pause = true;
            }
            #[cfg(feature = "sectigo")]
            13 => {
                let plugin = get_ca_plugin(debug)?;

                let csr = prompt_path(
                    &mut app_config.ui_state,
                    "ca_submit.csr",
                    "Path to .csr file",
                    None,
                )?;
                let default_crt = derive_path(&csr, "crt");

                let out = prompt_path(
                    &mut app_config.ui_state,
                    "ca_submit.output",
                    "Path to output signed .crt file",
                    non_empty(default_crt),
                )?;

                let job = build_ca_submit_job(
                    &csr,
                    &out,
                    app_config.ui_state.workflow.active_profile.as_deref(),
                );

                let description: String = input("Optional enrollment description (comments)")
                    .required(false)
                    .interact()?;
                let desc_opt = if description.is_empty() {
                    None
                } else {
                    Some(description)
                };

                let selected_code = if std::env::var("SECTIGO_PRODUCT_CODE").is_err() {
                    let profiles = plugin.list_profiles(debug)?;

                    if profiles.is_empty() {
                        clear_screen()?;
                        eprintln!("No SSL profiles available");
                        pause_for_menu_return()?;
                        continue;
                    }

                    let mut sel = select("Select SSL Certificate Type");
                    for (idx, profile) in profiles.iter().enumerate() {
                        sel = sel.item(idx, &profile.name, "");
                    }
                    let selection = sel.interact()?;

                    Some(profiles[selection].id.clone())
                } else {
                    None
                };

                println!("\n╔═══════════════════════════════════════════════════════════════╗");
                println!("║                    CSR Details Review                        ║");
                println!("╚═══════════════════════════════════════════════════════════════╝\n");

                match ssl_toolbox_core::key_csr::extract_csr_details(&csr) {
                    Ok((cn, sans)) => {
                        println!("  CommonName: {}", cn);
                        if sans.is_empty() {
                            println!("  SANs: None");
                        } else {
                            println!("  SANs:");
                            for san in &sans {
                                println!("    • {}", san);
                            }
                        }
                        println!();

                        let confirm_result =
                            confirm("Do you want to continue with enrollment?").interact()?;
                        if !confirm_result {
                            clear_screen()?;
                            println!("Enrollment cancelled.");
                            pause_for_menu_return()?;
                            continue;
                        }
                    }
                    Err(e) => {
                        eprintln!("Warning: Could not extract CSR details: {}", e);
                        eprintln!("Continuing with enrollment anyway...");
                    }
                }

                let csr_content = std::fs::read_to_string(&csr)?;
                let options = ssl_toolbox_ca::SubmitOptions {
                    description: desc_opt,
                    product_code: selected_code,
                    term_days: None,
                };
                show_preview_and_confirm(&job)?;

                let request_id = plugin.submit_csr(&csr_content, &options, debug)?;

                clear_screen()?;
                println!("Waiting 20 seconds for certificate to be processed...");
                std::thread::sleep(std::time::Duration::from_secs(20));

                let cert_content = plugin.collect_cert(
                    &request_id,
                    ssl_toolbox_ca::CollectFormat::PemCert,
                    debug,
                )?;
                std::fs::write(&out, &cert_content)?;

                display::display_cert_chain(
                    cert_content.as_bytes(),
                    "Downloaded Certificate Details",
                );
                println!("Success: Certificate saved to {}", display_path(&out));
                finalize_job(&mut app_config.ui_state, job);
                should_pause = true;
            }
            #[cfg(feature = "sectigo")]
            14 => {
                let plugin = get_ca_plugin(debug)?;
                clear_screen()?;
                match plugin.list_profiles(debug) {
                    Ok(profiles) => {
                        if profiles.is_empty() {
                            println!("\nNo SSL profiles available.");
                        } else {
                            println!(
                                "\n╔═══════════════════════════════════════════════════════════════╗"
                            );
                            println!(
                                "║              Available SSL Certificate Types                 ║"
                            );
                            println!(
                                "╚═══════════════════════════════════════════════════════════════╝\n"
                            );

                            for profile in profiles {
                                println!("  • {} (ID: {})", profile.name, profile.id);
                                if !profile.terms.is_empty() {
                                    let terms: Vec<String> = profile
                                        .terms
                                        .iter()
                                        .map(|t| format!("{} days", t))
                                        .collect();
                                    println!("    Available terms: {}", terms.join(", "));
                                }
                                println!();
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error fetching SSL profiles: {}", e);
                    }
                }
                should_pause = true;
            }
            _ => break,
        }

        if should_pause {
            pause_for_menu_return()?;
        }
    }

    outro("Goodbye!")?;
    Ok(())
}

fn prompt_config_inputs(
    defaults: &CsrDefaults,
    profile: Option<WorkflowProfile>,
) -> Result<ConfigInputs> {
    let common_name: String = input("Common Name").interact()?;

    let country: String = if defaults.country.is_empty() {
        input("Country (2-letter code)").interact()?
    } else {
        input("Country (2-letter code)")
            .default_input(&defaults.country)
            .interact()?
    };

    let state: String = if defaults.state.is_empty() {
        input("State or Province").interact()?
    } else {
        input("State or Province")
            .default_input(&defaults.state)
            .interact()?
    };

    let locality: String = if defaults.locality.is_empty() {
        input("Locality / City").interact()?
    } else {
        input("Locality / City")
            .default_input(&defaults.locality)
            .interact()?
    };

    let organization: String = if defaults.organization.is_empty() {
        input("Organization").interact()?
    } else {
        input("Organization")
            .default_input(&defaults.organization)
            .interact()?
    };

    let org_unit: String = if defaults.org_unit.is_empty() {
        input("Organizational Unit").interact()?
    } else {
        input("Organizational Unit")
            .default_input(&defaults.org_unit)
            .interact()?
    };

    let email: String = if defaults.email.is_empty() {
        input("Email Address").interact()?
    } else {
        input("Email Address")
            .default_input(&defaults.email)
            .interact()?
    };

    let mut san_dns: Vec<String> = Vec::new();
    println!("\nAdditional DNS SANs (the CN is already included as DNS.1).");
    println!("Press Enter with no input when done.");
    loop {
        let dns: String = input("Additional DNS SAN (or Enter to skip)")
            .required(false)
            .interact()?;
        if dns.is_empty() {
            break;
        }
        san_dns.push(dns);
    }

    let mut san_ips: Vec<String> = Vec::new();
    println!("\nIP SANs (optional). Press Enter with no input when done.");
    loop {
        let ip: String = input("IP SAN (or Enter to skip)")
            .required(false)
            .interact()?;
        if ip.is_empty() {
            break;
        }
        san_ips.push(ip);
    }

    let preferred_key_size = profile.as_ref().map(|item| item.key_size).unwrap_or(2048);
    let key_size: u32 = if preferred_key_size == 4096 {
        select("Key size")
            .item(4096, "4096", "Profile default — stronger but slower")
            .item(2048, "2048", "More widely compatible")
            .interact()?
    } else {
        select("Key size")
            .item(2048, "2048", "Default — widely compatible")
            .item(4096, "4096", "Stronger but slower")
            .interact()?
    };

    let preferred_eku = profile
        .as_ref()
        .map(|item| item.extended_key_usage)
        .unwrap_or("serverAuth");
    let extended_key_usage: String = match preferred_eku {
        "clientAuth" => select("Extended Key Usage")
            .item(
                "clientAuth".to_string(),
                "Client Auth",
                "Profile default — TLS client certificates",
            )
            .item(
                "serverAuth".to_string(),
                "Server Auth",
                "TLS server certificates",
            )
            .item(
                "serverAuth, clientAuth".to_string(),
                "Both (mTLS)",
                "Mutual TLS — server and client auth",
            )
            .interact()?,
        "serverAuth, clientAuth" => select("Extended Key Usage")
            .item(
                "serverAuth, clientAuth".to_string(),
                "Both (mTLS)",
                "Profile default — server and client auth",
            )
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
            .interact()?,
        _ => select("Extended Key Usage")
            .item(
                "serverAuth".to_string(),
                "Server Auth",
                "Profile/default — TLS server certificates",
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
            .interact()?,
    };

    Ok(ConfigInputs {
        common_name,
        country,
        state,
        locality,
        organization,
        org_unit,
        email,
        san_dns,
        san_ips,
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
    for (i, dns) in inputs.san_dns.iter().enumerate() {
        println!("    DNS.{} = {}", i + 2, dns);
    }
    for (i, ip) in inputs.san_ips.iter().enumerate() {
        println!("    IP.{}  = {}", i + 1, ip);
    }
    println!("  Output:       {}", output_path);
    println!();
}

fn build_new_config_job(
    output_path: &str,
    profile: Option<&str>,
    inputs: Option<&ConfigInputs>,
) -> JobRecord {
    let mut job = JobRecord::new(
        ActionKind::NewConfig,
        format!("Generate config {}", display_path(output_path)),
    )
    .with_output("config", output_path.to_string());
    if let Some(profile) = profile {
        job.profile = Some(profile.to_string());
    }
    if let Some(inputs) = inputs {
        job = job
            .with_replay_data("common_name", inputs.common_name.clone())
            .with_replay_data("country", inputs.country.clone())
            .with_replay_data("state", inputs.state.clone())
            .with_replay_data("locality", inputs.locality.clone())
            .with_replay_data("organization", inputs.organization.clone())
            .with_replay_data("org_unit", inputs.org_unit.clone())
            .with_replay_data("email", inputs.email.clone())
            .with_replay_data(
                "san_dns",
                serde_json::to_string(&inputs.san_dns).unwrap_or_else(|_| "[]".to_string()),
            )
            .with_replay_data(
                "san_ips",
                serde_json::to_string(&inputs.san_ips).unwrap_or_else(|_| "[]".to_string()),
            )
            .with_replay_data("key_size", inputs.key_size.to_string())
            .with_replay_data("extended_key_usage", inputs.extended_key_usage.clone());
    }
    job
}

fn build_generate_job(conf: &str, key: &str, csr: &str, profile: Option<&str>) -> JobRecord {
    let mut job = JobRecord::new(
        ActionKind::Generate,
        format!("Generate key and CSR from {}", display_path(conf)),
    )
    .with_input("config", conf.to_string())
    .with_output("key", key.to_string())
    .with_output("csr", csr.to_string());
    if let Some(profile) = profile {
        job.profile = Some(profile.to_string());
    }
    job
}

fn build_ca_submit_job(csr: &str, out: &str, profile: Option<&str>) -> JobRecord {
    let mut job = JobRecord::new(
        ActionKind::CaSubmit,
        format!("Submit CSR {}", display_path(csr)),
    )
    .with_input("csr", csr.to_string())
    .with_output("cert", out.to_string());
    if let Some(profile) = profile {
        job.profile = Some(profile.to_string());
    }
    job
}

fn stored_new_config_inputs(job: &JobRecord) -> Option<ConfigInputs> {
    let read = |key: &str| job.replay_data.get(key).cloned();
    Some(ConfigInputs {
        common_name: read("common_name")?,
        country: read("country")?,
        state: read("state")?,
        locality: read("locality")?,
        organization: read("organization")?,
        org_unit: read("org_unit")?,
        email: read("email")?,
        san_dns: serde_json::from_str(&read("san_dns")?).ok()?,
        san_ips: serde_json::from_str(&read("san_ips")?).ok()?,
        key_size: read("key_size")?.parse().ok()?,
        extended_key_usage: read("extended_key_usage")?,
    })
}

enum NewConfigReplaySource {
    Stored(Box<ConfigInputs>),
    Prompt,
}

fn new_config_replay_source(job: &JobRecord) -> NewConfigReplaySource {
    stored_new_config_inputs(job)
        .map(|inputs| NewConfigReplaySource::Stored(Box::new(inputs)))
        .unwrap_or(NewConfigReplaySource::Prompt)
}

fn build_replay_pfx_job(
    kind: ActionKind,
    key: &str,
    cert: &str,
    chain: Option<&str>,
    out_key: &str,
    out: &str,
) -> JobRecord {
    let mut job = JobRecord::new(
        kind,
        format!(
            "Repeat {} from {}",
            if matches!(kind, ActionKind::CreateLegacyPfx) {
                "legacy PFX"
            } else {
                "PFX"
            },
            display_path(cert)
        ),
    )
    .with_input("key", key.to_string())
    .with_input("cert", cert.to_string())
    .with_output(out_key, out.to_string());
    if let Some(chain) = chain {
        job.inputs.insert("chain".to_string(), chain.to_string());
    }
    job
}

fn finalize_job_if_success(state: &mut settings::UiState, job: JobRecord, success: bool) {
    if success {
        finalize_job(state, job);
    }
}

fn derive_path(base_path: &str, new_ext: &str) -> String {
    let path = Path::new(base_path);
    if let Some(stem) = path.file_stem() {
        let parent = path.parent().unwrap_or(Path::new(""));
        let new_path = parent.join(format!("{}.{}", stem.to_string_lossy(), new_ext));
        return new_path.display().to_string();
    }
    String::new()
}

fn build_main_menu() -> Vec<PaletteEntry> {
    let mut items = vec![
        PaletteEntry {
            action: 0,
            alias: "g",
            title: "Generate Key and CSR",
            description: "Build a new key and CSR from a config file",
            keywords: &["generate", "csr", "key"],
        },
        PaletteEntry {
            action: 1,
            alias: "pfx",
            title: "Create PFX",
            description: "Combine key and cert into a PFX file",
            keywords: &["pkcs12", "bundle", "export"],
        },
        PaletteEntry {
            action: 2,
            alias: "legacy",
            title: "Create Legacy PFX",
            description: "Convert existing PFX to TripleDES-SHA1 format",
            keywords: &["legacy", "3des", "pkcs12"],
        },
        PaletteEntry {
            action: 3,
            alias: "new",
            title: "Generate New OpenSSL Config",
            description: "Build a .cnf file from scratch via prompts",
            keywords: &["config", "openssl", "profile"],
        },
        PaletteEntry {
            action: 4,
            alias: "config",
            title: "Generate Config from Cert/CSR",
            description: "Create a .cnf file from existing data",
            keywords: &["config", "csr", "certificate"],
        },
        PaletteEntry {
            action: 5,
            alias: "cert",
            title: "View Certificate Details",
            description: "Display details of an existing certificate",
            keywords: &["inspect", "certificate", "x509"],
        },
        PaletteEntry {
            action: 6,
            alias: "csr",
            title: "View CSR Details",
            description: "Display details of an existing CSR",
            keywords: &["inspect", "csr"],
        },
        PaletteEntry {
            action: 7,
            alias: "vpfx",
            title: "View PFX Contents",
            description: "Display certs and chain inside a PFX/PKCS12 file",
            keywords: &["inspect", "pfx", "pkcs12"],
        },
        PaletteEntry {
            action: 8,
            alias: "https",
            title: "Verify HTTPS Endpoint",
            description: "Check TLS cert and protocol for an HTTPS server",
            keywords: &["verify", "tls", "https"],
        },
        PaletteEntry {
            action: 9,
            alias: "ldaps",
            title: "Verify LDAPS Endpoint",
            description: "Check TLS cert and protocol for an LDAPS server",
            keywords: &["verify", "tls", "ldap"],
        },
        PaletteEntry {
            action: 10,
            alias: "smtp",
            title: "Verify SMTP Endpoint",
            description: "Check TLS cert via SMTP STARTTLS",
            keywords: &["verify", "tls", "mail"],
        },
        PaletteEntry {
            action: 11,
            alias: "convert",
            title: "Convert Certificate Format",
            description: "Convert between PEM, DER, and Base64",
            keywords: &["convert", "pem", "der", "base64"],
        },
        PaletteEntry {
            action: 12,
            alias: "id",
            title: "Identify Certificate Format",
            description: "Auto-detect a certificate file's format",
            keywords: &["identify", "detect", "format"],
        },
    ];

    #[cfg(feature = "sectigo")]
    {
        items.push(PaletteEntry {
            action: 13,
            alias: "submit",
            title: "CA: Submit CSR",
            description: "Submit CSR to CA for signing",
            keywords: &["ca", "submit", "sectigo"],
        });
        items.push(PaletteEntry {
            action: 14,
            alias: "profiles",
            title: "CA: List Profiles",
            description: "View available SSL certificate types",
            keywords: &["ca", "profiles", "sectigo"],
        });
    }

    items.push(PaletteEntry {
        action: 99,
        alias: "q",
        title: "Exit",
        description: "Close the application",
        keywords: &["quit", "exit"],
    });

    items
}

#[derive(Clone, Copy)]
struct MenuGroup {
    title: &'static str,
    color: Color,
    aliases: &'static [&'static str],
}

fn compact_menu_title(item: &PaletteEntry) -> &'static str {
    match item.alias {
        "g" => "Generate CSR",
        "pfx" => "Create PFX",
        "legacy" => "Legacy PFX",
        "new" => "New Config",
        "config" => "Config from Cert/CSR",
        "cert" => "View Certificate",
        "csr" => "View CSR",
        "vpfx" => "View PFX",
        "https" => "Verify HTTPS",
        "ldaps" => "Verify LDAPS",
        "smtp" => "Verify SMTP",
        "convert" => "Convert Format",
        "id" => "Identify Format",
        "submit" => "Submit CSR",
        "profiles" => "List Profiles",
        "q" => "Exit",
        _ => item.title,
    }
}

fn menu_groups() -> Vec<MenuGroup> {
    vec![
        MenuGroup {
            title: "Build",
            color: Color::Green,
            aliases: &["g", "pfx", "legacy", "new", "config"],
        },
        MenuGroup {
            title: "Inspect",
            color: Color::Magenta,
            aliases: &["cert", "csr", "vpfx", "id"],
        },
        MenuGroup {
            title: "Verify",
            color: Color::Blue,
            aliases: &["https", "ldaps", "smtp"],
        },
        MenuGroup {
            title: "Tools",
            color: Color::Cyan,
            aliases: &["convert"],
        },
        MenuGroup {
            title: "CA",
            color: Color::Yellow,
            aliases: &["submit", "profiles"],
        },
        MenuGroup {
            title: "Exit",
            color: Color::Red,
            aliases: &["q"],
        },
    ]
}

fn grouped_menu_sections(items: &[PaletteEntry]) -> Vec<(MenuGroup, Vec<String>)> {
    menu_groups()
        .into_iter()
        .filter_map(|group| {
            let entries = group
                .aliases
                .iter()
                .filter_map(|alias| {
                    items
                        .iter()
                        .enumerate()
                        .find(|(_, item)| item.alias == *alias)
                        .map(|(index, item)| {
                            format!(
                                "{:>2} [{}] {}",
                                index + 1,
                                item.alias,
                                compact_menu_title(item)
                            )
                        })
                })
                .collect::<Vec<_>>();

            if entries.is_empty() {
                None
            } else {
                Some((group, entries))
            }
        })
        .collect()
}

fn menu_column_width(sections: &[(MenuGroup, Vec<String>)]) -> usize {
    sections
        .iter()
        .flat_map(|(group, entries)| {
            std::iter::once(group.title.len()).chain(entries.iter().map(|entry| entry.len()))
        })
        .max()
        .unwrap_or(24)
        .clamp(24, 34)
        + 2
}

fn menu_column_count(column_width: usize) -> usize {
    let terminal_width = terminal::size()
        .map(|(width, _)| width as usize)
        .unwrap_or(120);

    if terminal_width >= (column_width * 3) + 8 {
        3
    } else if terminal_width >= (column_width * 2) + 6 {
        2
    } else {
        1
    }
}

fn print_main_menu(items: &[PaletteEntry]) {
    let sections = grouped_menu_sections(items);
    let column_width = menu_column_width(&sections);
    let column_count = menu_column_count(column_width);

    println!();
    println!("{}", "Quick Menu".with(Color::Cyan).bold());
    println!("{}", "Choose a number, alias, or /query.".dark_grey());
    println!(
        "{}",
        "Grouped view keeps the default menu compact; /query shows detailed matches.".dark_grey()
    );
    println!();

    for group_row in sections.chunks(column_count) {
        for (index, (group, _)) in group_row.iter().enumerate() {
            if index > 0 {
                print!("  ");
            }
            print!(
                "{}",
                format!("{:<width$}", group.title, width = column_width)
                    .with(group.color)
                    .bold()
            );
        }
        println!();

        let max_group_height = group_row
            .iter()
            .map(|(_, entries)| entries.len())
            .max()
            .unwrap_or(0);

        for line_index in 0..max_group_height {
            for (index, (group, entries)) in group_row.iter().enumerate() {
                if index > 0 {
                    print!("  ");
                }
                let entry = entries.get(line_index).map(String::as_str).unwrap_or("");
                print!(
                    "{}",
                    format!("{entry:<width$}", width = column_width).with(group.color)
                );
            }
            println!();
        }

        println!();
    }

    println!(
        "{} {}  {} {}  {} {}  {} {}  {} {}  {} {}",
        "Palette".dark_grey(),
        "/query".with(Color::Yellow).bold(),
        "Repeat".dark_grey(),
        ".".with(Color::Cyan).bold(),
        "Clone".dark_grey(),
        ",".with(Color::Cyan).bold(),
        "History".dark_grey(),
        "h".with(Color::Magenta).bold(),
        "Workspace".dark_grey(),
        "w".with(Color::Green).bold(),
        "Profile".dark_grey(),
        "p".with(Color::Blue).bold()
    );
}

fn prompt_main_menu_choice(items: &[PaletteEntry], state: &mut settings::UiState) -> Result<i32> {
    let default_choice = if state.last_menu_choice.is_empty() {
        items.first().map(|item| item.alias).unwrap_or("q")
    } else {
        state.last_menu_choice.as_str()
    };

    let raw: String = input("Choose an action (number or alias)")
        .default_input(default_choice)
        .interact()?;
    let choice = raw.trim().to_ascii_lowercase();

    if choice.starts_with('/') {
        let matches = search_palette(choice.trim_start_matches('/'), items);
        if matches.is_empty() {
            eprintln!("No command palette matches for '{}'.", raw);
            return Ok(-1);
        }
        if matches.len() == 1 {
            state.remember_menu_choice(&matches[0].alias);
            persist_ui_state(state);
            return Ok(matches[0].action);
        }

        let mut picker = select("Command Palette");
        for item in matches.iter().take(8) {
            picker = picker.item(
                item.action,
                format!("{} [{}]", item.title, item.alias),
                item.description.clone(),
            );
        }
        let selection = picker.interact()?;
        if let Some(entry) = items.iter().find(|entry| entry.action == selection) {
            state.remember_menu_choice(entry.alias);
            persist_ui_state(state);
        }
        return Ok(selection);
    }

    match choice.as_str() {
        "." | "repeat" => return Ok(-2),
        "," | "clone" => return Ok(-3),
        "h" | "history" | "recent" => return Ok(-4),
        "w" | "workspace" | "files" => return Ok(-5),
        "p" | "profile" => return Ok(-6),
        _ => {}
    }

    if let Ok(number) = choice.parse::<usize>()
        && number > 0
        && let Some(item) = items.get(number - 1)
    {
        state.remember_menu_choice(item.alias);
        persist_ui_state(state);
        return Ok(item.action);
    }

    if let Some(item) = items.iter().find(|item| item.alias == choice) {
        state.remember_menu_choice(item.alias);
        persist_ui_state(state);
        return Ok(item.action);
    }

    if matches!(choice.as_str(), "exit" | "quit") {
        state.remember_menu_choice("q");
        persist_ui_state(state);
        return Ok(99);
    }

    eprintln!("Unknown selection '{}'. Use a menu number or alias.", raw);
    Ok(-1)
}

fn prompt_path(
    state: &mut settings::UiState,
    key: &str,
    label: &str,
    suggested: Option<String>,
) -> Result<String> {
    prompt_path_inner(state, key, label, suggested, true).map(|value| value.unwrap_or_default())
}

fn prompt_optional_path(
    state: &mut settings::UiState,
    key: &str,
    label: &str,
    suggested: Option<String>,
) -> Result<Option<String>> {
    prompt_path_inner(state, key, label, suggested, false)
}

fn prompt_path_inner(
    state: &mut settings::UiState,
    key: &str,
    label: &str,
    suggested: Option<String>,
    required: bool,
) -> Result<Option<String>> {
    let workspace = current_workspace_snapshot();
    let preferred_kind = preferred_artifact_kind_for_key(key);
    let detected_workflow = workspace.detect_workflow();
    let default_value = suggested
        .or_else(|| state.recent_path(key).map(ToOwned::to_owned))
        .or_else(|| preferred_kind.and_then(|kind| state.workflow.get(kind).map(ToOwned::to_owned)))
        .or_else(|| {
            preferred_kind.and_then(|kind| detected_workflow.get(kind).map(ToOwned::to_owned))
        });
    let default_display = default_value.as_ref().map(|value| display_path(value));
    let suggestions = path_suggestions(
        "",
        preferred_kind,
        &state.recent_paths,
        &state.workflow,
        &workspace,
    );

    if !suggestions.is_empty() {
        println!("Suggestions:");
        for (index, suggestion) in suggestions.iter().take(5).enumerate() {
            println!("  {}. {}", index + 1, display_path(&suggestion.path));
        }
        println!("Use a number, `?` for picker, a partial path for completion, or type a path.");
    }

    let mut builder = input(label);
    if let Some(default_display) = default_display.as_deref() {
        builder = builder.default_input(default_display);
    }
    if !required {
        builder = builder.required(false);
    }

    let raw: String = builder.interact()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    if trimmed == "?" && !suggestions.is_empty() {
        let mut picker = select(label);
        for suggestion in suggestions.iter().take(12) {
            let display = display_path(&suggestion.path);
            picker = picker.item(suggestion.path.clone(), display, suggestion.path.clone());
        }
        let picked = picker.interact()?;
        state.remember_path(key, &picked);
        persist_ui_state(state);
        return Ok(Some(picked));
    }

    if let Ok(number) = trimmed.parse::<usize>()
        && number > 0
        && let Some(suggestion) = suggestions.get(number - 1)
    {
        state.remember_path(key, &suggestion.path);
        persist_ui_state(state);
        return Ok(Some(suggestion.path.clone()));
    }

    let filtered = path_suggestions(
        trimmed,
        preferred_kind,
        &state.recent_paths,
        &state.workflow,
        &workspace,
    );
    if let Some(completed) = workflow::complete_path(trimmed, &filtered) {
        state.remember_path(key, &completed);
        persist_ui_state(state);
        return Ok(Some(completed));
    }

    let resolved = resolve_path(&raw);
    state.remember_path(key, &resolved);
    persist_ui_state(state);
    Ok(Some(resolved))
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

fn resolve_path(raw: &str) -> String {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    settings::resolve_path_from(&cwd, raw).display().to_string()
}

fn display_path(path: &str) -> String {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    settings::display_path_from(&cwd, Path::new(path))
}

fn persist_ui_state(state: &settings::UiState) {
    if let Err(error) = settings::save_state(state) {
        eprintln!("Warning: could not save breadcrumb state: {}", error);
    }
}

fn current_workspace_snapshot() -> WorkspaceSnapshot {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    WorkspaceSnapshot::scan(&cwd)
}

fn preferred_artifact_kind_for_key(key: &str) -> Option<ArtifactKind> {
    if key.contains("config") || key.contains(".conf") || key.contains(".cnf") {
        Some(ArtifactKind::Config)
    } else if key.contains("key") {
        Some(ArtifactKind::Key)
    } else if key.contains("csr") {
        Some(ArtifactKind::Csr)
    } else if key.contains("chain") {
        Some(ArtifactKind::Chain)
    } else if key.contains("legacy") {
        Some(ArtifactKind::LegacyPfx)
    } else if key.contains("pfx") {
        Some(ArtifactKind::Pfx)
    } else if key.contains("cert") || key.contains("crt") {
        Some(ArtifactKind::Cert)
    } else {
        None
    }
}

fn print_dashboard(state: &settings::UiState, workspace: &WorkspaceSnapshot) {
    fn artifact_color(kind: ArtifactKind) -> Color {
        match kind {
            ArtifactKind::Config => Color::Green,
            ArtifactKind::Key | ArtifactKind::Csr | ArtifactKind::Cert | ArtifactKind::Chain => {
                Color::Magenta
            }
            ArtifactKind::Pfx | ArtifactKind::LegacyPfx => Color::Cyan,
        }
    }

    fn home_relative(path: &Path) -> String {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from));
        if let Some(home) = home
            && let Ok(rel) = path.strip_prefix(&home)
        {
            let shown = rel.display().to_string();
            return if shown.is_empty() {
                "~".to_string()
            } else {
                format!("~/{}", shown)
            };
        }
        path.display().to_string()
    }

    fn label(text: &str) -> String {
        format!("{:<10}", text).dark_grey().bold().to_string()
    }

    let pad = "          "; // 10 spaces, matches label width

    println!();
    println!(
        " {}  {}",
        label("Workspace"),
        home_relative(&workspace.root)
    );

    if let Some(profile) = &state.workflow.active_profile {
        println!(
            " {}  {}",
            label("Profile"),
            profile.clone().with(Color::Yellow).bold()
        );
    }

    let pairs = state.workflow.artifact_pairs();
    for (i, (kind, path)) in pairs.iter().enumerate() {
        let row_label = if i == 0 {
            label("Workflow")
        } else {
            pad.to_string()
        };
        let key = format!("{:<10}", kind.key())
            .with(artifact_color(*kind))
            .bold();
        let shown = home_relative(Path::new(path));
        let exists = Path::new(path).exists();
        if exists {
            println!(" {}  {} {}", row_label, key, shown);
        } else {
            println!(
                " {}  {} {} {}",
                row_label,
                key,
                shown,
                "(missing)".with(Color::Red).bold()
            );
        }
    }

    if let Some(job) = state.recent_jobs.first() {
        println!(
            " {}  {}",
            label("Last Job"),
            job.summary.clone().with(Color::Yellow)
        );
    }

    let top_files = workspace.top_files(5);
    if !top_files.is_empty() {
        let joined = top_files
            .into_iter()
            .map(|p| home_relative(Path::new(&p)))
            .collect::<Vec<_>>()
            .join(", ");
        println!(" {}  {}", label("Files"), joined.dark_grey());
    }
}

fn print_workspace_overview(workspace: &WorkspaceSnapshot) {
    println!();
    println!("Workspace Files");
    if workspace.files.is_empty() {
        println!("  No likely certificate artifacts detected.");
        return;
    }
    for file in &workspace.files {
        println!("  {:<10} {}", file.kind.display(), file.path.display());
    }
}

fn print_recent_jobs(state: &settings::UiState) {
    println!();
    println!("Recent Jobs");
    if state.recent_jobs.is_empty() {
        println!("  No recorded jobs yet.");
        return;
    }
    for (index, job) in state.recent_jobs.iter().take(10).enumerate() {
        println!("  {}. {} [{}]", index + 1, job.summary, job.kind.alias());
    }
    println!("Use `.` to repeat the latest job or `,` to clone it with edits.");
}

fn select_active_profile(state: &mut settings::UiState) -> Result<()> {
    let mut picker = select("Choose an active workflow profile").item(
        "__none__".to_string(),
        "No Profile",
        "Use only saved org defaults",
    );
    for profile in builtin_profiles() {
        picker = picker.item(
            profile.id.to_string(),
            profile.name,
            profile.description.to_string(),
        );
    }

    let selection = picker.interact()?;
    state.workflow.active_profile = if selection == "__none__" {
        None
    } else {
        Some(selection)
    };
    persist_ui_state(state);
    Ok(())
}

fn effective_csr_defaults(state: &settings::UiState, base: &CsrDefaults) -> CsrDefaults {
    let mut defaults = base.clone();
    if let Some(profile_id) = &state.workflow.active_profile
        && let Some(profile) = profile_by_id(profile_id)
    {
        merge_profile_defaults(&mut defaults, &profile);
    }
    defaults
}

fn active_profile(state: &settings::UiState) -> Option<WorkflowProfile> {
    state
        .workflow
        .active_profile
        .as_deref()
        .and_then(profile_by_id)
}

fn merge_profile_defaults(target: &mut CsrDefaults, profile: &WorkflowProfile) {
    if !profile.csr_defaults.country.is_empty() {
        target.country = profile.csr_defaults.country.clone();
    }
    if !profile.csr_defaults.state.is_empty() {
        target.state = profile.csr_defaults.state.clone();
    }
    if !profile.csr_defaults.locality.is_empty() {
        target.locality = profile.csr_defaults.locality.clone();
    }
    if !profile.csr_defaults.organization.is_empty() {
        target.organization = profile.csr_defaults.organization.clone();
    }
    if !profile.csr_defaults.org_unit.is_empty() {
        target.org_unit = profile.csr_defaults.org_unit.clone();
    }
    if !profile.csr_defaults.email.is_empty() {
        target.email = profile.csr_defaults.email.clone();
    }
}

fn merge_detected_workflow(
    target: &mut workflow::WorkflowMemory,
    detected: &workflow::WorkflowMemory,
) {
    for (kind, value) in detected.artifact_pairs() {
        if target.get(kind).is_none() {
            target.set(kind, value);
        }
    }
}

fn show_preview_and_confirm(job: &JobRecord) -> Result<()> {
    let preview = build_preview(job);
    if preview.lines.is_empty() {
        return Ok(());
    }

    println!();
    println!("Planned Action: {}", preview.title);
    for (label, value) in preview.lines {
        println!("  {:<16} {}", label, display_path(&value));
    }
    let confirmed = confirm("Proceed with this action?")
        .initial_value(true)
        .interact()?;
    if confirmed {
        Ok(())
    } else {
        Err(anyhow::anyhow!("Action cancelled"))
    }
}

fn convert_output_suggestion(input_path: &str, format: &str) -> Option<String> {
    match format {
        "der" => non_empty(derive_path(input_path, "der")),
        "pem" => non_empty(derive_path(input_path, "pem")),
        "base64" => non_empty(derive_path(input_path, "b64")),
        _ => suggest_output_path(input_path, ArtifactKind::Cert),
    }
}

fn convert_format_for_replay(job: &JobRecord, output_path: &str) -> String {
    job.replay_data.get("format").cloned().unwrap_or_else(|| {
        if output_path.ends_with(".der") {
            "der".to_string()
        } else if output_path.ends_with(".pem") {
            "pem".to_string()
        } else {
            "base64".to_string()
        }
    })
}

fn finalize_job(state: &mut settings::UiState, job: JobRecord) {
    apply_job_to_workflow(&mut state.workflow, &job);
    push_recent_job(&mut state.recent_jobs, job.clone());
    persist_ui_state(state);
    print_validation_plan(&job);
    print_next_steps(&job, &state.workflow);
}

fn print_validation_plan(job: &JobRecord) {
    let steps = validation_steps(job);
    if steps.is_empty() {
        return;
    }

    println!("Validation:");
    for step in steps {
        println!("  - {}: {}", step.label, step.command);
    }
}

fn print_next_steps(job: &JobRecord, memory: &workflow::WorkflowMemory) {
    let steps = next_steps(job, memory);
    if steps.is_empty() {
        return;
    }

    println!("Next Steps:");
    for step in steps {
        println!("  - {}", step);
    }
}

fn replay_recent_job(state: &mut settings::UiState, debug: bool, clone: bool) -> Result<()> {
    let Some(job) = state.recent_jobs.first().cloned() else {
        eprintln!("No recent jobs to replay.");
        return Ok(());
    };

    match job.kind {
        ActionKind::Generate => replay_generate(state, &job, clone),
        ActionKind::CreatePfx => replay_pfx(state, &job, clone, false),
        ActionKind::CreateLegacyPfx => replay_pfx(state, &job, clone, true),
        ActionKind::NewConfig => replay_new_config(state, &job, clone),
        ActionKind::ConfigFromExisting => replay_config_from_existing(state, &job, clone),
        ActionKind::ViewCert => replay_view_cert(state, &job, clone),
        ActionKind::ViewCsr => replay_view_csr(state, &job, clone),
        ActionKind::ViewPfx => replay_view_pfx(state, &job, clone),
        ActionKind::VerifyHttps => replay_verify_https(state, &job, clone),
        ActionKind::VerifyLdaps => replay_verify_ldaps(state, &job, clone),
        ActionKind::VerifySmtp => replay_verify_smtp(state, &job, clone),
        ActionKind::Convert => replay_convert(state, &job, clone),
        ActionKind::Identify => replay_identify(state, &job, clone),
        #[cfg(feature = "sectigo")]
        ActionKind::CaSubmit => replay_ca_submit(state, &job, clone, debug),
        ActionKind::CaProfiles => {
            eprintln!("The CA profile listing action does not have a replay path.");
            Ok(())
        }
        #[cfg(not(feature = "sectigo"))]
        ActionKind::CaSubmit => {
            let _ = debug;
            eprintln!("The CA submit action is unavailable in this build.");
            Ok(())
        }
    }
}

fn seeded_value(job: &JobRecord, key: &str) -> Option<String> {
    job.inputs
        .get(key)
        .or_else(|| job.outputs.get(key))
        .cloned()
}

fn seeded_bool(job: &JobRecord, key: &str, default: bool) -> bool {
    seeded_value(job, key)
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" | "enabled" => Some(true),
            "0" | "false" | "no" | "off" | "disabled" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedEndpointInput {
    host: String,
    port: Option<u16>,
}

fn normalize_tls_endpoint_target(
    raw_host: &str,
    port: u16,
    default_port: u16,
) -> Result<(String, u16)> {
    let parsed = parse_endpoint_input(raw_host)?;
    let effective_port = if port == default_port {
        parsed.port.unwrap_or(port)
    } else {
        port
    };
    Ok((parsed.host, effective_port))
}

fn parse_endpoint_input(raw: &str) -> Result<ParsedEndpointInput> {
    let mut candidate = raw.trim().trim_matches(|ch| ch == '"' || ch == '\'');
    if candidate.is_empty() {
        return Err(anyhow::anyhow!("Host/domain input is empty"));
    }

    let mut had_scheme = false;
    if let Some((_, rest)) = candidate.split_once("://") {
        had_scheme = true;
        candidate = rest;
    }

    if had_scheme && candidate.starts_with('/') {
        return Err(anyhow::anyhow!(
            "Could not find a valid host/domain in the input"
        ));
    }

    candidate = candidate.trim_start_matches('/');

    if let Some((before, _)) = candidate.split_once(['/', '?', '#']) {
        candidate = before;
    }

    if let Some((_, host_part)) = candidate.rsplit_once('@') {
        candidate = host_part;
    }

    let candidate = candidate.trim();
    if candidate.is_empty() {
        return Err(anyhow::anyhow!(
            "Could not find a valid host/domain in the input"
        ));
    }
    if candidate.chars().any(char::is_whitespace) {
        return Err(anyhow::anyhow!(
            "Host/domain contains whitespace after cleanup: {candidate}"
        ));
    }

    if let Some(rest) = candidate.strip_prefix('[') {
        let (host, remainder) = rest
            .split_once(']')
            .ok_or_else(|| anyhow::anyhow!("Invalid bracketed host/domain: {candidate}"))?;
        let port = if remainder.is_empty() {
            None
        } else if let Some(raw_port) = remainder.strip_prefix(':') {
            Some(parse_endpoint_port(raw_port, candidate)?)
        } else {
            return Err(anyhow::anyhow!("Invalid host/domain input: {candidate}"));
        };

        return Ok(ParsedEndpointInput {
            host: host.to_string(),
            port,
        });
    }

    if let Some((host, raw_port)) = candidate.rsplit_once(':')
        && !host.is_empty()
        && !raw_port.is_empty()
        && raw_port.chars().all(|ch| ch.is_ascii_digit())
        && !host.contains(':')
    {
        return Ok(ParsedEndpointInput {
            host: host.to_string(),
            port: Some(parse_endpoint_port(raw_port, candidate)?),
        });
    }

    Ok(ParsedEndpointInput {
        host: candidate.to_string(),
        port: None,
    })
}

fn parse_endpoint_port(raw_port: &str, original: &str) -> Result<u16> {
    raw_port.parse::<u16>().map_err(|_| {
        anyhow::anyhow!("Invalid port in host/domain input `{original}`: `{raw_port}`")
    })
}

fn write_verify_results(path: &str, report: &str) -> Result<()> {
    std::fs::write(path, report)
        .with_context(|| format!("Failed to write verify results to {}", path))?;
    println!("Saved report to {}", path);
    Ok(())
}

fn format_connect_target(host: &str) -> Cow<'_, str> {
    if host.contains(':') {
        Cow::Owned(format!("[{host}]"))
    } else {
        Cow::Borrowed(host)
    }
}

fn replay_generate(state: &mut settings::UiState, job: &JobRecord, clone: bool) -> Result<()> {
    let conf = if clone {
        prompt_path(
            state,
            "generate.conf",
            "Path to openssl.conf",
            seeded_value(job, "config"),
        )?
    } else {
        seeded_value(job, "config").ok_or_else(|| anyhow::anyhow!("Missing config path"))?
    };
    let key = if clone {
        prompt_path(
            state,
            "generate.key",
            "Path to output .key file",
            seeded_value(job, "key"),
        )?
    } else {
        seeded_value(job, "key").ok_or_else(|| anyhow::anyhow!("Missing key path"))?
    };
    let csr = if clone {
        prompt_path(
            state,
            "generate.csr",
            "Path to output .csr file",
            seeded_value(job, "csr"),
        )?
    } else {
        seeded_value(job, "csr").ok_or_else(|| anyhow::anyhow!("Missing csr path"))?
    };

    let replay_job = build_generate_job(&conf, &key, &csr, job.profile.as_deref());
    show_preview_and_confirm(&replay_job)?;
    let pass: String = password("Enter password for private key").interact()?;
    ssl_toolbox_core::key_csr::generate_key_and_csr(&conf, &key, &csr, &pass)?;
    clear_screen()?;
    println!(
        "Success: Generated {} and {}",
        display_path(&key),
        display_path(&csr)
    );
    finalize_job(state, replay_job);
    Ok(())
}

fn replay_pfx(
    state: &mut settings::UiState,
    job: &JobRecord,
    clone: bool,
    legacy: bool,
) -> Result<()> {
    let key = if legacy && job.inputs.contains_key("pfx") && !clone {
        seeded_value(job, "pfx").ok_or_else(|| anyhow::anyhow!("Missing input PFX"))?
    } else if clone {
        prompt_path(
            state,
            if legacy {
                "pfx_legacy.input"
            } else {
                "pfx.key"
            },
            if legacy {
                "Path to existing PFX file"
            } else {
                "Path to .key file"
            },
            seeded_value(job, if legacy { "pfx" } else { "key" }),
        )?
    } else {
        seeded_value(job, if legacy { "pfx" } else { "key" })
            .ok_or_else(|| anyhow::anyhow!("Missing replay input"))?
    };

    if legacy && job.inputs.contains_key("pfx") {
        let out = if clone {
            prompt_path(
                state,
                "pfx_legacy.output",
                "Path to output legacy PFX file",
                seeded_value(job, "legacy_pfx"),
            )?
        } else {
            seeded_value(job, "legacy_pfx")
                .ok_or_else(|| anyhow::anyhow!("Missing legacy output"))?
        };
        let replay_job = JobRecord::new(
            ActionKind::CreateLegacyPfx,
            format!("Repeat legacy conversion {}", display_path(&key)),
        )
        .with_input("pfx", key.clone())
        .with_output("legacy_pfx", out.clone());
        show_preview_and_confirm(&replay_job)?;
        let input_pass: String = password("Enter password for input PFX").interact()?;
        let output_pass: String = password("Enter password for output PFX").interact()?;
        let pfx_bytes = std::fs::read(&key)?;
        ssl_toolbox_core::pfx::create_pfx_legacy_3des(&pfx_bytes, &input_pass, &out, &output_pass)?;
        clear_screen()?;
        println!(
            "Success: Legacy PFX (TripleDES-SHA1) created at {}",
            display_path(&out)
        );
        finalize_job(state, replay_job);
        return Ok(());
    }

    let cert = if clone {
        prompt_path(
            state,
            "pfx.cert",
            "Path to signed .crt file",
            seeded_value(job, "cert"),
        )?
    } else {
        seeded_value(job, "cert").ok_or_else(|| anyhow::anyhow!("Missing cert path"))?
    };
    let chain = if clone {
        prompt_optional_path(
            state,
            "pfx.chain",
            "Path to chain file (optional)",
            seeded_value(job, "chain"),
        )?
    } else {
        seeded_value(job, "chain")
    };
    let out_key = if legacy { "legacy_pfx" } else { "pfx" };
    let out = if clone {
        prompt_path(
            state,
            "pfx.output",
            "Path to output .pfx file",
            seeded_value(job, out_key),
        )?
    } else {
        seeded_value(job, out_key).ok_or_else(|| anyhow::anyhow!("Missing PFX output"))?
    };
    let replay_job = build_replay_pfx_job(
        if legacy {
            ActionKind::CreateLegacyPfx
        } else {
            ActionKind::CreatePfx
        },
        &key,
        &cert,
        chain.as_deref(),
        out_key,
        &out,
    );
    show_preview_and_confirm(&replay_job)?;
    let key_pass: String =
        password("Enter password for private key (or press Enter if not encrypted)")
            .allow_empty()
            .interact()?;
    let key_pass_opt = if key_pass.is_empty() {
        None
    } else {
        Some(key_pass.as_str())
    };
    let pfx_pass: String = password("Enter password for PFX export").interact()?;
    if legacy {
        ssl_toolbox_core::pfx::create_pfx_legacy(
            &key,
            &cert,
            chain.as_deref(),
            &out,
            key_pass_opt,
            &pfx_pass,
        )?;
    } else {
        ssl_toolbox_core::pfx::create_pfx(
            &key,
            &cert,
            chain.as_deref(),
            &out,
            key_pass_opt,
            &pfx_pass,
        )?;
    }
    clear_screen()?;
    println!(
        "Success: {} created at {}",
        if legacy { "Legacy PFX" } else { "PFX" },
        display_path(&out)
    );
    finalize_job(state, replay_job);
    Ok(())
}

fn replay_new_config(state: &mut settings::UiState, job: &JobRecord, clone: bool) -> Result<()> {
    let out = if clone {
        prompt_path(
            state,
            "new_config.output",
            "Output .cnf file path",
            seeded_value(job, "config"),
        )?
    } else {
        seeded_value(job, "config").ok_or_else(|| anyhow::anyhow!("Missing config output"))?
    };
    let inputs = match new_config_replay_source(job) {
        NewConfigReplaySource::Stored(inputs) => *inputs,
        NewConfigReplaySource::Prompt => {
            let mut defaults = CsrDefaults::default();
            let replay_profile = job
                .profile
                .as_deref()
                .and_then(profile_by_id)
                .or_else(|| active_profile(state));
            if let Some(profile) = replay_profile.clone() {
                merge_profile_defaults(&mut defaults, &profile);
            }
            prompt_config_inputs(&defaults, replay_profile)?
        }
    };
    let replay_job = build_new_config_job(&out, job.profile.as_deref(), Some(&inputs));
    show_preview_and_confirm(&replay_job)?;
    ssl_toolbox_core::config::generate_conf_from_inputs(&inputs, &out)?;
    clear_screen()?;
    println!("Success: OpenSSL config written to {}", display_path(&out));
    finalize_job(state, replay_job);
    Ok(())
}

fn replay_config_from_existing(
    state: &mut settings::UiState,
    job: &JobRecord,
    clone: bool,
) -> Result<()> {
    let source = if clone {
        prompt_path(
            state,
            "config_from_existing.input",
            "Path to existing .cer or .csr",
            seeded_value(job, "source"),
        )?
    } else {
        seeded_value(job, "source").ok_or_else(|| anyhow::anyhow!("Missing source path"))?
    };
    let out = if clone {
        prompt_path(
            state,
            "config_from_existing.output",
            "Path to output .conf file",
            seeded_value(job, "config"),
        )?
    } else {
        seeded_value(job, "config").ok_or_else(|| anyhow::anyhow!("Missing config output"))?
    };
    let replay_job = JobRecord::new(
        ActionKind::ConfigFromExisting,
        format!("Repeat config from {}", display_path(&source)),
    )
    .with_input("source", source.clone())
    .with_output("config", out.clone());
    show_preview_and_confirm(&replay_job)?;
    let is_csr = source.ends_with(".csr");
    ssl_toolbox_core::config::generate_conf_from_cert_or_csr(&source, &out, is_csr)?;
    clear_screen()?;
    println!("Success: OpenSSL config written to {}", display_path(&out));
    finalize_job(state, replay_job);
    Ok(())
}

fn replay_view_cert(state: &mut settings::UiState, job: &JobRecord, clone: bool) -> Result<()> {
    let cert = if clone {
        prompt_path(
            state,
            "view_cert.input",
            "Path to certificate file (.crt, .cer, .pem)",
            seeded_value(job, "cert"),
        )?
    } else {
        seeded_value(job, "cert").ok_or_else(|| anyhow::anyhow!("Missing certificate path"))?
    };
    let cert_content = std::fs::read(&cert)?;
    clear_screen()?;
    display::display_cert_chain(&cert_content, "Certificate Details");
    finalize_job(
        state,
        JobRecord::new(
            ActionKind::ViewCert,
            format!("Inspect certificate {}", display_path(&cert)),
        )
        .with_input("cert", cert),
    );
    Ok(())
}

fn replay_view_csr(state: &mut settings::UiState, job: &JobRecord, clone: bool) -> Result<()> {
    let csr = if clone {
        prompt_path(
            state,
            "view_csr.input",
            "Path to CSR file (.csr)",
            seeded_value(job, "csr"),
        )?
    } else {
        seeded_value(job, "csr").ok_or_else(|| anyhow::anyhow!("Missing CSR path"))?
    };
    let (cn, sans) = ssl_toolbox_core::key_csr::extract_csr_details(&csr)?;
    clear_screen()?;
    println!("CommonName: {}", cn);
    for san in sans {
        println!("  {}", san);
    }
    finalize_job(
        state,
        JobRecord::new(
            ActionKind::ViewCsr,
            format!("Inspect CSR {}", display_path(&csr)),
        )
        .with_input("csr", csr),
    );
    Ok(())
}

fn replay_view_pfx(state: &mut settings::UiState, job: &JobRecord, clone: bool) -> Result<()> {
    let pfx = if clone {
        prompt_path(
            state,
            "view_pfx.input",
            "Path to PFX file (.pfx, .p12)",
            seeded_value(job, "pfx"),
        )?
    } else {
        seeded_value(job, "pfx").ok_or_else(|| anyhow::anyhow!("Missing PFX path"))?
    };
    let pfx_pass: String = password("Enter PFX password").interact()?;
    let pfx_bytes = std::fs::read(&pfx)?;
    let details = ssl_toolbox_core::pfx::extract_pfx_bundle_details(&pfx_bytes, &pfx_pass)?;
    clear_screen()?;
    display::display_pfx_details(&details, "PFX Contents");
    finalize_job(
        state,
        JobRecord::new(
            ActionKind::ViewPfx,
            format!("Inspect PFX {}", display_path(&pfx)),
        )
        .with_input("pfx", pfx),
    );
    Ok(())
}

fn replay_verify_https(state: &mut settings::UiState, job: &JobRecord, clone: bool) -> Result<()> {
    replay_verify_endpoint(
        state,
        job,
        clone,
        ActionKind::VerifyHttps,
        "https_host",
        443,
    )
}

fn replay_verify_ldaps(state: &mut settings::UiState, job: &JobRecord, clone: bool) -> Result<()> {
    replay_verify_endpoint(
        state,
        job,
        clone,
        ActionKind::VerifyLdaps,
        "ldaps_host",
        636,
    )
}

fn replay_verify_smtp(state: &mut settings::UiState, job: &JobRecord, clone: bool) -> Result<()> {
    replay_verify_endpoint(state, job, clone, ActionKind::VerifySmtp, "smtp_host", 587)
}

fn replay_verify_endpoint(
    state: &mut settings::UiState,
    job: &JobRecord,
    clone: bool,
    kind: ActionKind,
    host_key: &str,
    default_port: u16,
) -> Result<()> {
    let host = if clone {
        let label = match kind {
            ActionKind::VerifyHttps => "Hostname (e.g. example.com)",
            ActionKind::VerifyLdaps => "Hostname (e.g. ldap.example.com)",
            ActionKind::VerifySmtp => "SMTP hostname (e.g. smtp.gmail.com)",
            _ => "Hostname",
        };
        input(label)
            .default_input(seeded_value(job, host_key).as_deref().unwrap_or(""))
            .interact()?
    } else {
        seeded_value(job, host_key).ok_or_else(|| anyhow::anyhow!("Missing host"))?
    };
    let port = seeded_value(job, "port")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(default_port);
    let (host, port) = if matches!(kind, ActionKind::VerifyHttps | ActionKind::VerifyLdaps) {
        normalize_tls_endpoint_target(&host, port, default_port)?
    } else {
        (host, port)
    };
    let replay_job = JobRecord::new(kind, format!("Repeat {} {host}:{port}", kind.title()))
        .with_input(host_key, host.clone())
        .with_input("port", port.to_string());
    let verify = confirm("Validate certificate?")
        .initial_value(true)
        .interact()?;
    let full_scan = if matches!(kind, ActionKind::VerifyHttps | ActionKind::VerifyLdaps) {
        confirm("Scan all supported protocol/cipher suites?")
            .initial_value(seeded_bool(job, "full_scan", false))
            .interact()?
    } else {
        false
    };
    let replay_job = replay_job.with_input("full_scan", full_scan.to_string());
    clear_screen()?;
    println!(
        "\nConnecting to {}:{}...",
        format_connect_target(&host),
        port
    );
    match kind {
        ActionKind::VerifyHttps | ActionKind::VerifyLdaps => {
            let result = ssl_toolbox_core::tls::connect_and_check(&host, port, verify, full_scan)?;
            display::display_tls_check_result(&result, kind.title());
        }
        ActionKind::VerifySmtp => {
            let result = ssl_toolbox_core::smtp::connect_and_check_smtp(&host, port, verify)?;
            display::display_tls_check_result(&result, kind.title());
        }
        _ => {}
    }
    finalize_job(state, replay_job);
    Ok(())
}

fn replay_convert(state: &mut settings::UiState, job: &JobRecord, clone: bool) -> Result<()> {
    let input_path = if clone {
        prompt_path(
            state,
            "convert.input",
            "Path to certificate file",
            seeded_value(job, "input"),
        )?
    } else {
        seeded_value(job, "input").ok_or_else(|| anyhow::anyhow!("Missing convert input"))?
    };
    let output_path = if clone {
        prompt_path(
            state,
            "convert.output",
            "Path to output file",
            seeded_value(job, "output"),
        )?
    } else {
        seeded_value(job, "output").ok_or_else(|| anyhow::anyhow!("Missing convert output"))?
    };
    let format = convert_format_for_replay(job, &output_path);
    let replay_job = JobRecord::new(
        ActionKind::Convert,
        format!("Repeat convert {}", display_path(&input_path)),
    )
    .with_input("input", input_path.clone())
    .with_output("output", output_path.clone());
    show_preview_and_confirm(&replay_job)?;
    match format.as_str() {
        "der" => ssl_toolbox_core::convert::pem_to_der(&input_path, &output_path)?,
        "pem" => ssl_toolbox_core::convert::der_to_pem(&input_path, &output_path)?,
        _ => ssl_toolbox_core::convert::pem_to_base64(&input_path, &output_path)?,
    }
    clear_screen()?;
    println!(
        "Success: Converted artifact saved to {}",
        display_path(&output_path)
    );
    finalize_job(state, replay_job);
    Ok(())
}

fn replay_identify(state: &mut settings::UiState, job: &JobRecord, clone: bool) -> Result<()> {
    let input_path = if clone {
        prompt_path(
            state,
            "identify.input",
            "Path to certificate file",
            seeded_value(job, "input"),
        )?
    } else {
        seeded_value(job, "input").ok_or_else(|| anyhow::anyhow!("Missing identify input"))?
    };
    let data = std::fs::read(&input_path)?;
    let format = ssl_toolbox_core::convert::detect_format(&data);
    clear_screen()?;
    println!(
        "Format: {}",
        ssl_toolbox_core::convert::format_description(format)
    );
    finalize_job(
        state,
        JobRecord::new(
            ActionKind::Identify,
            format!("Identify artifact {}", display_path(&input_path)),
        )
        .with_input("input", input_path),
    );
    Ok(())
}

#[cfg(feature = "sectigo")]
fn replay_ca_submit(
    state: &mut settings::UiState,
    job: &JobRecord,
    clone: bool,
    debug: bool,
) -> Result<()> {
    let plugin = get_ca_plugin(debug)?;
    let csr = if clone {
        prompt_path(
            state,
            "ca_submit.csr",
            "Path to .csr file",
            seeded_value(job, "csr"),
        )?
    } else {
        seeded_value(job, "csr").ok_or_else(|| anyhow::anyhow!("Missing CSR path"))?
    };
    let out = if clone {
        prompt_path(
            state,
            "ca_submit.output",
            "Path to output signed .crt file",
            seeded_value(job, "cert"),
        )?
    } else {
        seeded_value(job, "cert").ok_or_else(|| anyhow::anyhow!("Missing output cert"))?
    };
    let replay_job = build_ca_submit_job(&csr, &out, job.profile.as_deref());
    show_preview_and_confirm(&replay_job)?;
    let csr_content = std::fs::read_to_string(&csr)?;
    let request_id = plugin.submit_csr(
        &csr_content,
        &ssl_toolbox_ca::SubmitOptions {
            description: None,
            product_code: None,
            term_days: None,
        },
        debug,
    )?;
    clear_screen()?;
    println!("Waiting 20 seconds for certificate to be processed...");
    std::thread::sleep(std::time::Duration::from_secs(20));
    let cert_content =
        plugin.collect_cert(&request_id, ssl_toolbox_ca::CollectFormat::PemCert, debug)?;
    std::fs::write(&out, &cert_content)?;
    display::display_cert_chain(cert_content.as_bytes(), "Downloaded Certificate Details");
    finalize_job(state, replay_job);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config_inputs() -> ConfigInputs {
        ConfigInputs {
            common_name: "svc.example.com".to_string(),
            country: "US".to_string(),
            state: "Texas".to_string(),
            locality: "Austin".to_string(),
            organization: "Example Corp".to_string(),
            org_unit: "Platform".to_string(),
            email: "pki@example.com".to_string(),
            san_dns: vec!["svc.example.com".to_string(), "svc.internal".to_string()],
            san_ips: vec!["10.0.0.5".to_string()],
            key_size: 4096,
            extended_key_usage: "serverAuth, clientAuth".to_string(),
        }
    }

    #[test]
    fn finalize_job_if_success_skips_failed_jobs() {
        let mut state = settings::UiState::default();
        let job = JobRecord::new(ActionKind::ViewCert, "Inspect missing cert")
            .with_input("cert", "missing.crt");

        finalize_job_if_success(&mut state, job, false);

        assert!(state.recent_jobs.is_empty());
        assert!(state.workflow.cert.is_none());
    }

    #[test]
    fn replay_pfx_job_preserves_optional_chain() {
        let job = build_replay_pfx_job(
            ActionKind::CreatePfx,
            "server.key",
            "server.crt",
            Some("chain.pem"),
            "pfx",
            "server.pfx",
        );

        assert_eq!(
            job.inputs.get("chain").map(String::as_str),
            Some("chain.pem")
        );
    }

    #[test]
    fn convert_replay_prefers_recorded_format_over_suffix() {
        let job = JobRecord::new(ActionKind::Convert, "Repeat convert input.pem")
            .with_input("input", "input.pem")
            .with_output("output", "output.pem")
            .with_replay_data("format", "base64");

        assert_eq!(convert_format_for_replay(&job, "output.pem"), "base64");
    }

    #[test]
    fn replay_jobs_preserve_profile_metadata() {
        let generate = build_generate_job(
            "server.cnf",
            "server.key",
            "server.csr",
            Some("internal-ca"),
        );
        assert_eq!(generate.profile.as_deref(), Some("internal-ca"));

        let ca_submit = build_ca_submit_job("server.csr", "server.crt", Some("internal-ca"));
        assert_eq!(ca_submit.profile.as_deref(), Some("internal-ca"));
    }

    #[test]
    fn new_config_job_round_trips_inputs_for_replay() {
        let inputs = sample_config_inputs();
        let job = build_new_config_job("server.cnf", Some("internal-ca"), Some(&inputs));
        let restored = stored_new_config_inputs(&job).expect("stored config inputs");

        assert_eq!(restored.common_name, inputs.common_name);
        assert_eq!(restored.country, inputs.country);
        assert_eq!(restored.state, inputs.state);
        assert_eq!(restored.locality, inputs.locality);
        assert_eq!(restored.organization, inputs.organization);
        assert_eq!(restored.org_unit, inputs.org_unit);
        assert_eq!(restored.email, inputs.email);
        assert_eq!(restored.san_dns, inputs.san_dns);
        assert_eq!(restored.san_ips, inputs.san_ips);
        assert_eq!(restored.key_size, inputs.key_size);
        assert_eq!(restored.extended_key_usage, inputs.extended_key_usage);
    }

    #[test]
    fn old_new_config_jobs_fall_back_to_prompt_mode() {
        let job = JobRecord::new(ActionKind::NewConfig, "Generate config server.cnf")
            .with_output("config", "server.cnf");

        assert!(matches!(
            new_config_replay_source(&job),
            NewConfigReplaySource::Prompt
        ));
    }

    #[test]
    fn parse_endpoint_input_accepts_https_url_with_port() {
        let parsed = parse_endpoint_input("https://host.example.com:443").expect("parsed input");

        assert_eq!(
            parsed,
            ParsedEndpointInput {
                host: "host.example.com".to_string(),
                port: Some(443),
            }
        );
    }

    #[test]
    fn parse_endpoint_input_strips_path_query_fragment_and_userinfo() {
        let parsed = parse_endpoint_input("https://user:pass@example.com:8443/path?a=b#frag")
            .expect("parsed input");

        assert_eq!(
            parsed,
            ParsedEndpointInput {
                host: "example.com".to_string(),
                port: Some(8443),
            }
        );
    }

    #[test]
    fn normalize_tls_endpoint_target_uses_embedded_port_when_default_was_requested() {
        let normalized =
            normalize_tls_endpoint_target("ldaps://ldap.example.com:1636/ou=People", 636, 636)
                .expect("normalized target");

        assert_eq!(normalized, ("ldap.example.com".to_string(), 1636));
    }

    #[test]
    fn normalize_tls_endpoint_target_preserves_explicit_non_default_port() {
        let normalized = normalize_tls_endpoint_target("https://example.com:8443", 9443, 443)
            .expect("normalized target");

        assert_eq!(normalized, ("example.com".to_string(), 9443));
    }

    #[test]
    fn parse_endpoint_input_rejects_empty_host_after_cleanup() {
        let err = parse_endpoint_input("https:///path").expect_err("invalid input");
        assert!(
            err.to_string().contains("valid host/domain"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn build_main_menu_keeps_expected_verify_group_aliases() {
        let items = build_main_menu();
        let aliases = items.iter().map(|item| item.alias).collect::<Vec<_>>();

        assert!(aliases.contains(&"https"));
        assert!(aliases.contains(&"ldaps"));
        assert!(aliases.contains(&"smtp"));
        assert!(aliases.contains(&"q"));
    }

    #[test]
    fn grouped_menu_sections_include_horizontal_groups_with_entries() {
        let items = build_main_menu();
        let sections = grouped_menu_sections(&items);

        assert_eq!(
            sections.first().map(|(group, _)| group.title),
            Some("Build")
        );
        assert!(
            sections
                .iter()
                .any(|(group, entries)| group.title == "Verify"
                    && entries.iter().any(|entry| entry.contains("[https]")))
        );
        assert!(sections.iter().any(|(group, entries)| group.title == "Exit"
            && entries.iter().any(|entry| entry.contains("[q]"))));
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
            Some(Commands::VerifyHttps {
                host,
                port,
                no_verify,
                full_scan,
                out,
            }) => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
                assert!(!no_verify);
                assert!(!full_scan);
                assert_eq!(out.as_deref(), Some("report.txt"));
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
            Some(Commands::VerifyLdaps {
                host,
                port,
                no_verify,
                full_scan,
                out,
            }) => {
                assert_eq!(host, "ldap.example.com");
                assert_eq!(port, 636);
                assert!(!no_verify);
                assert!(!full_scan);
                assert_eq!(out.as_deref(), Some("ldaps.txt"));
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
            Some(Commands::VerifySmtp {
                host,
                port,
                no_verify,
                out,
            }) => {
                assert_eq!(host, "smtp.example.com");
                assert_eq!(port, 587);
                assert!(!no_verify);
                assert_eq!(out.as_deref(), Some("smtp.txt"));
            }
            _ => panic!("unexpected command"),
        }
    }
}

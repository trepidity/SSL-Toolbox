mod display;
mod settings;
#[cfg(target_os = "windows")]
mod win_certmgr;

use anyhow::Result;
use clap::{Parser, Subcommand};
use cliclack::{confirm, input, intro, outro, password, select};
use dotenvy::dotenv;
use std::path::{Path, PathBuf};

use ssl_toolbox_core::{ConfigInputs, CsrDefaults};

#[derive(Parser)]
#[command(name = "ssl-toolbox", author, version, about = "SSL/TLS Security Toolbox", long_about = None)]
struct Cli {
    /// Enable debug output
    #[arg(long, global = true)]
    debug: bool,

    /// Launch directly into the Windows Certificate Manager
    #[cfg(target_os = "windows")]
    #[arg(long, hide = true)]
    certmgr: bool,

    /// Resume location after elevation
    #[cfg(target_os = "windows")]
    #[arg(long, hide = true)]
    certmgr_location: Option<String>,

    /// Resume store after elevation
    #[cfg(target_os = "windows")]
    #[arg(long, hide = true)]
    certmgr_store: Option<String>,

    /// Resume selected certificate after elevation
    #[cfg(target_os = "windows")]
    #[arg(long, hide = true)]
    certmgr_thumbprint: Option<String>,

    /// Resume selected physical store after elevation
    #[cfg(target_os = "windows")]
    #[arg(long, hide = true)]
    certmgr_physical: Option<String>,

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
    /// Windows certificate store operations
    #[cfg(target_os = "windows")]
    #[command(subcommand)]
    CertStore(CertStoreCommands),
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

#[cfg(target_os = "windows")]
#[derive(Subcommand)]
enum CertStoreCommands {
    /// List store names at a location
    Stores {
        #[arg(short, long, default_value = "current-user")]
        location: String,
    },
    /// List certificates in a store
    List {
        #[arg(short, long, default_value = "current-user")]
        location: String,
        #[arg(short, long, default_value = "MY")]
        store: String,
    },
    /// Show a certificate by thumbprint
    Show {
        #[arg(short, long, default_value = "current-user")]
        location: String,
        #[arg(short, long, default_value = "MY")]
        store: String,
        #[arg(short, long)]
        thumbprint: String,
    },
    /// Import a certificate or PFX into a store
    Import {
        #[arg(short, long, default_value = "current-user")]
        location: String,
        #[arg(short, long, default_value = "MY")]
        store: String,
        #[arg(short, long)]
        file: String,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(long)]
        exportable: bool,
    },
    /// Export a certificate from a store
    Export {
        #[arg(short, long, default_value = "current-user")]
        location: String,
        #[arg(short, long, default_value = "MY")]
        store: String,
        #[arg(short, long)]
        thumbprint: String,
        #[arg(short, long)]
        out: String,
        #[arg(short, long, default_value = "pem")]
        format: String,
        #[arg(long)]
        pfx_password: Option<String>,
    },
    /// Delete a certificate from a store
    Delete {
        #[arg(short, long, default_value = "current-user")]
        location: String,
        #[arg(short, long, default_value = "MY")]
        store: String,
        #[arg(short, long)]
        thumbprint: String,
        #[arg(long)]
        force: bool,
    },
    /// Launch the interactive Windows certificate browser
    Browse,
}

fn main() -> Result<()> {
    let _ = dotenv();

    let cli = Cli::parse();

    #[cfg(target_os = "windows")]
    if cli.certmgr {
        return win_certmgr::launch_certmgr(Some(win_certmgr::ResumeArgs {
            location: cli.certmgr_location,
            store: cli.certmgr_store,
            thumbprint: cli.certmgr_thumbprint,
            physical: cli.certmgr_physical,
        }));
    }

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
            let inputs = prompt_config_inputs(&app_config.csr_defaults)?;
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
            match ssl_toolbox_core::pfx::extract_pfx_details(&pfx_bytes, &pfx_pass) {
                Ok(cert_chain) => {
                    display::display_cert_details_list(&cert_chain, "PFX Contents");
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
        } => {
            println!("\nConnecting to {}:{}...", host, port);
            let verify = !no_verify;
            match ssl_toolbox_core::tls::connect_and_check(&host, port, verify) {
                Ok(result) => {
                    display::display_tls_check_result(&result, "HTTPS Endpoint Verification");
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
        } => {
            println!("\nConnecting to {}:{}...", host, port);
            let verify = !no_verify;
            match ssl_toolbox_core::tls::connect_and_check(&host, port, verify) {
                Ok(result) => {
                    display::display_tls_check_result(&result, "LDAPS Endpoint Verification");
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
        } => {
            println!("\nConnecting to {}:{}...", host, port);
            let verify = !no_verify;
            match ssl_toolbox_core::smtp::connect_and_check_smtp(&host, port, verify) {
                Ok(result) => {
                    display::display_tls_check_result(
                        &result,
                        "SMTP STARTTLS Endpoint Verification",
                    );
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
        #[cfg(target_os = "windows")]
        Commands::CertStore(cmd) => match cmd {
            CertStoreCommands::Stores { location } => {
                win_certmgr::list_store_names(&location)?;
            }
            CertStoreCommands::List { location, store } => {
                win_certmgr::list_store_certs(&location, &store)?;
            }
            CertStoreCommands::Show {
                location,
                store,
                thumbprint,
            } => {
                win_certmgr::show_certificate_details(&location, &store, &thumbprint)?;
            }
            CertStoreCommands::Import {
                location,
                store,
                file,
                password,
                exportable,
            } => {
                win_certmgr::import_into_store(&location, &store, &file, password, exportable)?;
            }
            CertStoreCommands::Export {
                location,
                store,
                thumbprint,
                out,
                format,
                pfx_password,
            } => {
                win_certmgr::export_from_store(
                    &location,
                    &store,
                    &thumbprint,
                    &out,
                    &format,
                    pfx_password,
                )?;
            }
            CertStoreCommands::Delete {
                location,
                store,
                thumbprint,
                force,
            } => {
                win_certmgr::delete_from_store(&location, &store, &thumbprint, force)?;
            }
            CertStoreCommands::Browse => {
                win_certmgr::launch_certmgr(None)?;
            }
        },
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

fn run_interactive_menu(debug: bool) -> Result<()> {
    #[cfg(not(feature = "sectigo"))]
    let _ = debug;

    let mut app_config = settings::load_config();

    intro("SSL/TLS Security Toolbox")?;

    loop {
        let menu = build_main_menu();
        print_main_menu(&menu);
        let selection = prompt_main_menu_choice(&menu, &mut app_config.ui_state)?;

        match selection {
            -1 => continue,
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

                let pass: String = password("Enter password for private key").interact()?;
                ssl_toolbox_core::key_csr::generate_key_and_csr(&conf, &key, &csr, &pass)?;
                println!(
                    "Success: Generated {} and {}",
                    display_path(&key),
                    display_path(&csr)
                );
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

                if use_legacy {
                    ssl_toolbox_core::pfx::create_pfx_legacy(
                        &key,
                        &cert,
                        chain_opt,
                        &out,
                        key_pass_opt,
                        &pfx_pass,
                    )?;
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
                    println!("Success: PFX created at {}", display_path(&out));
                }
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

                let input_pass: String = password("Enter password for input PFX").interact()?;
                let output_pass: String = password("Enter password for output PFX").interact()?;

                let pfx_bytes = std::fs::read(&input_path)?;
                ssl_toolbox_core::pfx::create_pfx_legacy_3des(
                    &pfx_bytes,
                    &input_pass,
                    &out,
                    &output_pass,
                )?;
                println!(
                    "Success: Legacy PFX (TripleDES-SHA1) created at {}",
                    display_path(&out)
                );
            }
            3 => {
                let inputs = prompt_config_inputs(&app_config.csr_defaults)?;
                let default_path = format!("{}.cnf", inputs.common_name);
                let output_path = prompt_path(
                    &mut app_config.ui_state,
                    "new_config.output",
                    "Output .cnf file path",
                    Some(default_path),
                )?;
                print_config_summary(&inputs, &output_path);
                let confirmed: bool = confirm("Write this config file?").interact()?;
                if confirmed {
                    ssl_toolbox_core::config::generate_conf_from_inputs(&inputs, &output_path)?;
                    println!(
                        "Success: OpenSSL config written to {}",
                        display_path(&output_path)
                    );
                } else {
                    println!("Cancelled.");
                }
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
                let is_csr = input_path.ends_with(".csr");
                ssl_toolbox_core::config::generate_conf_from_cert_or_csr(
                    &input_path,
                    &out,
                    is_csr,
                )?;
                println!("Success: OpenSSL config written to {}", display_path(&out));
            }
            5 => {
                let input_path = prompt_path(
                    &mut app_config.ui_state,
                    "view_cert.input",
                    "Path to certificate file (.crt, .cer, .pem)",
                    None,
                )?;
                match std::fs::read(&input_path) {
                    Ok(cert_content) => {
                        display::display_cert_chain(&cert_content, "Certificate Details");
                    }
                    Err(e) => {
                        eprintln!("Error reading file: {}", e);
                    }
                }
            }
            6 => {
                let input_path = prompt_path(
                    &mut app_config.ui_state,
                    "view_csr.input",
                    "Path to CSR file (.csr)",
                    None,
                )?;
                println!("\n╔═══════════════════════════════════════════════════════════════╗");
                println!("║                        CSR Details                           ║");
                println!("╚═══════════════════════════════════════════════════════════════╝\n");
                match ssl_toolbox_core::key_csr::extract_csr_details(&input_path) {
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
            7 => {
                let input_path = prompt_path(
                    &mut app_config.ui_state,
                    "view_pfx.input",
                    "Path to PFX file (.pfx, .p12)",
                    None,
                )?;
                let pfx_pass: String = password("Enter PFX password").interact()?;
                match std::fs::read(&input_path) {
                    Ok(pfx_bytes) => {
                        match ssl_toolbox_core::pfx::extract_pfx_details(&pfx_bytes, &pfx_pass) {
                            Ok(cert_chain) => {
                                display::display_cert_details_list(&cert_chain, "PFX Contents");
                            }
                            Err(e) => {
                                eprintln!("Error: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading file: {}", e);
                    }
                }
            }
            8 => {
                let host: String = input("Hostname (e.g. example.com)").interact()?;
                let port_str: String = input("Port").default_input("443").interact()?;
                let port: u16 = port_str.parse().unwrap_or(443);
                let verify: bool = confirm("Validate certificate?")
                    .initial_value(true)
                    .interact()?;

                println!("\nConnecting to {}:{}...", host, port);
                match ssl_toolbox_core::tls::connect_and_check(&host, port, verify) {
                    Ok(result) => {
                        display::display_tls_check_result(&result, "HTTPS Endpoint Verification");
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                    }
                }
            }
            9 => {
                let host: String = input("Hostname (e.g. ldap.example.com)").interact()?;
                let port_str: String = input("Port").default_input("636").interact()?;
                let port: u16 = port_str.parse().unwrap_or(636);
                let verify: bool = confirm("Validate certificate?")
                    .initial_value(true)
                    .interact()?;

                println!("\nConnecting to {}:{}...", host, port);
                match ssl_toolbox_core::tls::connect_and_check(&host, port, verify) {
                    Ok(result) => {
                        display::display_tls_check_result(&result, "LDAPS Endpoint Verification");
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                    }
                }
            }
            10 => {
                let host: String = input("SMTP hostname (e.g. smtp.gmail.com)").interact()?;
                let port_str: String = input("Port").default_input("587").interact()?;
                let port: u16 = port_str.parse().unwrap_or(587);
                let verify: bool = confirm("Validate certificate?")
                    .initial_value(true)
                    .interact()?;

                println!("\nConnecting to {}:{}...", host, port);
                match ssl_toolbox_core::smtp::connect_and_check_smtp(&host, port, verify) {
                    Ok(result) => {
                        display::display_tls_check_result(
                            &result,
                            "SMTP STARTTLS Endpoint Verification",
                        );
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                    }
                }
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
                    non_empty(derive_path(
                        &input_path,
                        match format.as_str() {
                            "der" => "der",
                            "pem" => "pem",
                            "base64" => "b64",
                            _ => unreachable!(),
                        },
                    )),
                )?;

                match format.as_str() {
                    "der" => {
                        ssl_toolbox_core::convert::pem_to_der(&input_path, &output_path)?;
                        println!("Success: Converted to DER: {}", display_path(&output_path));
                    }
                    "pem" => {
                        ssl_toolbox_core::convert::der_to_pem(&input_path, &output_path)?;
                        println!("Success: Converted to PEM: {}", display_path(&output_path));
                    }
                    "base64" => {
                        ssl_toolbox_core::convert::pem_to_base64(&input_path, &output_path)?;
                        println!(
                            "Success: Converted to Base64: {}",
                            display_path(&output_path)
                        );
                    }
                    _ => unreachable!(),
                }
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
                println!("\nFile: {}", display_path(&input_path));
                println!("Format: {}", desc);
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
                        eprintln!("No SSL profiles available");
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
                            println!("Enrollment cancelled.");
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

                let request_id = plugin.submit_csr(&csr_content, &options, debug)?;

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
            }
            #[cfg(feature = "sectigo")]
            14 => {
                let plugin = get_ca_plugin(debug)?;
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
            }
            #[cfg(target_os = "windows")]
            20 => {
                outro("Launching Windows Certificate Manager")?;
                win_certmgr::launch_certmgr(None)?;
                intro("SSL/TLS Security Toolbox")?;
            }
            _ => break,
        }
    }

    outro("Goodbye!")?;
    Ok(())
}

fn prompt_config_inputs(defaults: &CsrDefaults) -> Result<ConfigInputs> {
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

    let key_size: u32 = select("Key size")
        .item(2048, "2048", "Default — widely compatible")
        .item(4096, "4096", "Stronger but slower")
        .interact()?;

    let extended_key_usage: String = select("Extended Key Usage")
        .item(
            "serverAuth".to_string(),
            "Server Auth",
            "TLS server certificates (default)",
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

fn derive_path(base_path: &str, new_ext: &str) -> String {
    let path = Path::new(base_path);
    if let Some(stem) = path.file_stem() {
        let parent = path.parent().unwrap_or(Path::new(""));
        let new_path = parent.join(format!("{}.{}", stem.to_string_lossy(), new_ext));
        return new_path.display().to_string();
    }
    String::new()
}

#[derive(Clone, Copy)]
struct MenuItem {
    action: i32,
    alias: &'static str,
    title: &'static str,
    description: &'static str,
}

fn build_main_menu() -> Vec<MenuItem> {
    let mut items = vec![
        MenuItem {
            action: 0,
            alias: "g",
            title: "Generate Key and CSR",
            description: "Build a new key and CSR from a config file",
        },
        MenuItem {
            action: 1,
            alias: "pfx",
            title: "Create PFX",
            description: "Combine key and cert into a PFX file",
        },
        MenuItem {
            action: 2,
            alias: "legacy",
            title: "Create Legacy PFX",
            description: "Convert existing PFX to TripleDES-SHA1 format",
        },
        MenuItem {
            action: 3,
            alias: "new",
            title: "Generate New OpenSSL Config",
            description: "Build a .cnf file from scratch via prompts",
        },
        MenuItem {
            action: 4,
            alias: "config",
            title: "Generate Config from Cert/CSR",
            description: "Create a .cnf file from existing data",
        },
        MenuItem {
            action: 5,
            alias: "cert",
            title: "View Certificate Details",
            description: "Display details of an existing certificate",
        },
        MenuItem {
            action: 6,
            alias: "csr",
            title: "View CSR Details",
            description: "Display details of an existing CSR",
        },
        MenuItem {
            action: 7,
            alias: "vpfx",
            title: "View PFX Contents",
            description: "Display certs and chain inside a PFX/PKCS12 file",
        },
        MenuItem {
            action: 8,
            alias: "https",
            title: "Verify HTTPS Endpoint",
            description: "Check TLS cert and protocol for an HTTPS server",
        },
        MenuItem {
            action: 9,
            alias: "ldaps",
            title: "Verify LDAPS Endpoint",
            description: "Check TLS cert and protocol for an LDAPS server",
        },
        MenuItem {
            action: 10,
            alias: "smtp",
            title: "Verify SMTP Endpoint",
            description: "Check TLS cert via SMTP STARTTLS",
        },
        MenuItem {
            action: 11,
            alias: "convert",
            title: "Convert Certificate Format",
            description: "Convert between PEM, DER, and Base64",
        },
        MenuItem {
            action: 12,
            alias: "id",
            title: "Identify Certificate Format",
            description: "Auto-detect a certificate file's format",
        },
    ];

    #[cfg(feature = "sectigo")]
    {
        items.push(MenuItem {
            action: 13,
            alias: "submit",
            title: "CA: Submit CSR",
            description: "Submit CSR to CA for signing",
        });
        items.push(MenuItem {
            action: 14,
            alias: "profiles",
            title: "CA: List Profiles",
            description: "View available SSL certificate types",
        });
    }

    #[cfg(target_os = "windows")]
    {
        items.push(MenuItem {
            action: 20,
            alias: "win",
            title: "Windows Certificate Manager",
            description: "Browse and manage Windows certificate stores",
        });
    }

    items.push(MenuItem {
        action: 99,
        alias: "q",
        title: "Exit",
        description: "Close the application",
    });

    items
}

fn print_main_menu(items: &[MenuItem]) {
    println!();
    println!("Quick Menu");
    for (index, item) in items.iter().enumerate() {
        println!(
            "  {:>2}. {:<8} {}",
            index + 1,
            format!("[{}]", item.alias),
            item.title
        );
        println!("      {}", item.description);
    }
    println!();
}

fn prompt_main_menu_choice(items: &[MenuItem], state: &mut settings::UiState) -> Result<i32> {
    let default_choice = if state.last_menu_choice.is_empty() {
        items.first().map(|item| item.alias).unwrap_or("q")
    } else {
        state.last_menu_choice.as_str()
    };

    let raw: String = input("Choose an action (number or alias)")
        .default_input(default_choice)
        .interact()?;
    let choice = raw.trim().to_ascii_lowercase();

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
    let default_value = suggested.or_else(|| state.recent_path(key).map(ToOwned::to_owned));
    let default_display = default_value.as_ref().map(|value| display_path(value));

    let mut builder = input(label);
    if let Some(default_display) = default_display.as_deref() {
        builder = builder.default_input(default_display);
    }
    if !required {
        builder = builder.required(false);
    }

    let raw: String = builder.interact()?;
    if raw.trim().is_empty() {
        return Ok(None);
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

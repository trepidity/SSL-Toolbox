mod display;

use anyhow::Result;
use clap::{Parser, Subcommand};
use cliclack::{confirm, input, intro, outro, password, select};
use dotenvy::dotenv;
use std::path::Path;

use ssl_toolbox_core::ConfigInputs;

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
    ssl_toolbox_ca_sectigo::SectigoPlugin::configure(debug)
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
            println!("Note: If your private key is encrypted, you'll be prompted for its password.");
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
            let inputs = prompt_config_inputs()?;
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
            println!(
                "\n╔═══════════════════════════════════════════════════════════════╗"
            );
            println!(
                "║                        CSR Details                           ║"
            );
            println!(
                "╚═══════════════════════════════════════════════════════════════╝\n"
            );

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
                        let terms: Vec<String> =
                            profile.terms.iter().map(|t| format!("{} days", t)).collect();
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
            println!(
                "\n╔═══════════════════════════════════════════════════════════════╗"
            );
            println!(
                "║                    CSR Details Review                        ║"
            );
            println!(
                "╚═══════════════════════════════════════════════════════════════╝\n"
            );

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
    intro("SSL/TLS Security Toolbox")?;

    loop {
        let mut menu = select("What would you like to do?")
            .item(0, "Generate Key and CSR", "Build a new key and CSR from a config file")
            .item(1, "Create PFX", "Combine key and cert into a PFX file")
            .item(
                2,
                "Create Legacy PFX",
                "Convert existing PFX to TripleDES-SHA1 format",
            )
            .item(
                3,
                "Generate New OpenSSL Config",
                "Build a .cnf file from scratch via prompts",
            )
            .item(
                4,
                "Generate Config from Cert/CSR",
                "Create a .cnf file from existing data",
            )
            .item(
                5,
                "View Certificate Details",
                "Display details of an existing certificate",
            )
            .item(6, "View CSR Details", "Display details of an existing CSR")
            .item(
                7,
                "View PFX Contents",
                "Display certs and chain inside a PFX/PKCS12 file",
            )
            .item(
                8,
                "Verify HTTPS Endpoint",
                "Check TLS cert and protocol for an HTTPS server",
            )
            .item(
                9,
                "Verify LDAPS Endpoint",
                "Check TLS cert and protocol for an LDAPS server",
            )
            .item(
                10,
                "Verify SMTP Endpoint",
                "Check TLS cert via SMTP STARTTLS",
            )
            .item(
                11,
                "Convert Certificate Format",
                "Convert between PEM, DER, and Base64",
            )
            .item(
                12,
                "Identify Certificate Format",
                "Auto-detect a certificate file's format",
            );

        #[cfg(feature = "sectigo")]
        {
            menu = menu
                .item(13, "CA: Submit CSR", "Submit CSR to CA for signing")
                .item(
                    14,
                    "CA: List Profiles",
                    "View available SSL certificate types",
                );
        }

        menu = menu.item(99, "Exit", "Close the application");

        let selection: i32 = menu.interact()?;

        match selection {
            0 => {
                let conf: String = input("Path to openssl.conf").interact()?;
                let default_key = derive_path(&conf, "key");
                let default_csr = derive_path(&conf, "csr");

                let key: String = if !default_key.is_empty() {
                    input("Path to output .key file")
                        .default_input(&default_key)
                        .interact()?
                } else {
                    input("Path to output .key file").interact()?
                };

                let csr: String = if !default_csr.is_empty() {
                    input("Path to output .csr file")
                        .default_input(&default_csr)
                        .interact()?
                } else {
                    input("Path to output .csr file").interact()?
                };

                let pass: String = password("Enter password for private key").interact()?;
                ssl_toolbox_core::key_csr::generate_key_and_csr(&conf, &key, &csr, &pass)?;
                println!("Success: Generated {} and {}", key, csr);
            }
            1 => {
                let key: String = input("Path to .key file").interact()?;
                let default_pfx = derive_path(&key, "pfx");

                let cert: String = input("Path to signed .crt file").interact()?;
                let chain: String = input("Path to chain file (optional)")
                    .required(false)
                    .interact()?;

                let out: String = if !default_pfx.is_empty() {
                    input("Path to output .pfx file")
                        .default_input(&default_pfx)
                        .interact()?
                } else {
                    input("Path to output .pfx file").interact()?
                };

                let use_legacy: bool = confirm("Use legacy TripleDES-SHA1 encryption?")
                    .initial_value(false)
                    .interact()?;

                println!("Note: If your private key is encrypted, you'll be prompted for its password.");
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
                let chain_opt = if chain.is_empty() {
                    None
                } else {
                    Some(chain.as_str())
                };

                if use_legacy {
                    ssl_toolbox_core::pfx::create_pfx_legacy(
                        &key,
                        &cert,
                        chain_opt,
                        &out,
                        key_pass_opt,
                        &pfx_pass,
                    )?;
                    println!("Success: Legacy PFX created at {}", out);
                } else {
                    ssl_toolbox_core::pfx::create_pfx(
                        &key,
                        &cert,
                        chain_opt,
                        &out,
                        key_pass_opt,
                        &pfx_pass,
                    )?;
                    println!("Success: PFX created at {}", out);
                }
            }
            2 => {
                let input_path: String = input("Path to existing PFX file").interact()?;
                let default_out = derive_path(&input_path, "legacy.pfx");
                let out: String = if !default_out.is_empty() {
                    input("Path to output legacy PFX file")
                        .default_input(&default_out)
                        .interact()?
                } else {
                    input("Path to output legacy PFX file").interact()?
                };

                let input_pass: String = password("Enter password for input PFX").interact()?;
                let output_pass: String = password("Enter password for output PFX").interact()?;

                let pfx_bytes = std::fs::read(&input_path)?;
                ssl_toolbox_core::pfx::create_pfx_legacy_3des(
                    &pfx_bytes,
                    &input_pass,
                    &out,
                    &output_pass,
                )?;
                println!("Success: Legacy PFX (TripleDES-SHA1) created at {}", out);
            }
            3 => {
                let inputs = prompt_config_inputs()?;
                let default_path = format!("{}.cnf", inputs.common_name);
                let output_path: String = input("Output .cnf file path")
                    .default_input(&default_path)
                    .interact()?;
                print_config_summary(&inputs, &output_path);
                let confirmed: bool = confirm("Write this config file?").interact()?;
                if confirmed {
                    ssl_toolbox_core::config::generate_conf_from_inputs(&inputs, &output_path)?;
                    println!("Success: OpenSSL config written to {}", output_path);
                } else {
                    println!("Cancelled.");
                }
            }
            4 => {
                let input_path: String = input("Path to existing .cer or .csr").interact()?;
                let out: String = input("Path to output .conf file").interact()?;
                let is_csr = input_path.ends_with(".csr");
                ssl_toolbox_core::config::generate_conf_from_cert_or_csr(
                    &input_path, &out, is_csr,
                )?;
                println!("Success: OpenSSL config written to {}", out);
            }
            5 => {
                let input_path: String =
                    input("Path to certificate file (.crt, .cer, .pem)").interact()?;
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
                let input_path: String = input("Path to CSR file (.csr)").interact()?;
                println!(
                    "\n╔═══════════════════════════════════════════════════════════════╗"
                );
                println!(
                    "║                        CSR Details                           ║"
                );
                println!(
                    "╚═══════════════════════════════════════════════════════════════╝\n"
                );
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
                let input_path: String = input("Path to PFX file (.pfx, .p12)").interact()?;
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
                        display::display_tls_check_result(
                            &result,
                            "HTTPS Endpoint Verification",
                        );
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
                        display::display_tls_check_result(
                            &result,
                            "LDAPS Endpoint Verification",
                        );
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
                let input_path: String = input("Path to certificate file").interact()?;
                let output_path: String = input("Path to output file").interact()?;
                let format: String = select("Target format")
                    .item("der".to_string(), "DER", "Binary ASN.1 encoding")
                    .item("pem".to_string(), "PEM", "Base64 with headers")
                    .item(
                        "base64".to_string(),
                        "Base64",
                        "Raw base64 (no PEM headers)",
                    )
                    .interact()?;

                match format.as_str() {
                    "der" => {
                        ssl_toolbox_core::convert::pem_to_der(&input_path, &output_path)?;
                        println!("Success: Converted to DER: {}", output_path);
                    }
                    "pem" => {
                        ssl_toolbox_core::convert::der_to_pem(&input_path, &output_path)?;
                        println!("Success: Converted to PEM: {}", output_path);
                    }
                    "base64" => {
                        ssl_toolbox_core::convert::pem_to_base64(&input_path, &output_path)?;
                        println!("Success: Converted to Base64: {}", output_path);
                    }
                    _ => unreachable!(),
                }
            }
            12 => {
                let input_path: String = input("Path to certificate file").interact()?;
                let data = std::fs::read(&input_path)?;
                let format = ssl_toolbox_core::convert::detect_format(&data);
                let desc = ssl_toolbox_core::convert::format_description(format);
                println!("\nFile: {}", input_path);
                println!("Format: {}", desc);
            }
            #[cfg(feature = "sectigo")]
            13 => {
                let plugin = get_ca_plugin(debug)?;

                let csr: String = input("Path to .csr file").interact()?;
                let default_crt = derive_path(&csr, "crt");

                let out: String = if !default_crt.is_empty() {
                    input("Path to output signed .crt file")
                        .default_input(&default_crt)
                        .interact()?
                } else {
                    input("Path to output signed .crt file").interact()?
                };

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

                println!(
                    "\n╔═══════════════════════════════════════════════════════════════╗"
                );
                println!(
                    "║                    CSR Details Review                        ║"
                );
                println!(
                    "╚═══════════════════════════════════════════════════════════════╝\n"
                );

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
                println!("Success: Certificate saved to {}", out);
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
            _ => break,
        }
    }

    outro("Goodbye!")?;
    Ok(())
}

fn prompt_config_inputs() -> Result<ConfigInputs> {
    let common_name: String = input("Common Name").interact()?;
    let country: String = input("Country (2-letter code)")
        .default_input("US")
        .interact()?;
    let state: String = input("State or Province")
        .default_input("Texas")
        .interact()?;
    let locality: String = input("Locality / City")
        .default_input("Dallas")
        .interact()?;
    let organization: String = input("Organization")
        .default_input("Baylor Scott & White Health")
        .interact()?;
    let org_unit: String = input("Organizational Unit")
        .default_input("IAM Engineering")
        .interact()?;
    let email: String = input("Email Address")
        .default_input("IAMENGINEERING@BSWHealth.org")
        .interact()?;

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
    println!(
        "\n╔═══════════════════════════════════════════════════════════════╗"
    );
    println!(
        "║                   Config Summary                            ║"
    );
    println!(
        "╚═══════════════════════════════════════════════════════════════╝\n"
    );
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

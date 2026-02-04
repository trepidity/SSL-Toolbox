mod openssl_utils;
mod sectigo;

use anyhow::Result;
use clap::{Parser, Subcommand};
use cliclack::{confirm, input, intro, outro, password, select};
use dotenvy::dotenv;
use std::path::Path;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
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
    /// Submit CSR to Sectigo and get signed certificate
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
}

/// Helper function to display certificate chain details
fn display_cert_chain(cert_content: &str, title: &str) {
    match openssl_utils::extract_cert_chain_details(cert_content) {
        Ok(cert_chain) => {
            if cert_chain.len() == 1 {
                println!("\n╔═══════════════════════════════════════════════════════════════╗");
                println!("║  {:^61}  ║", title);
                println!("╚═══════════════════════════════════════════════════════════════╝\n");
                
                let details = &cert_chain[0];
                println!("  CommonName: {}", details.common_name);
                println!("  Issuer: {}", details.issuer);
                println!("  Valid From: {}", details.not_before);
                println!("  Valid Until: {}", details.not_after);
                
                if details.sans.is_empty() {
                    println!("  SANs: None");
                } else {
                    println!("  SANs:");
                    for san in &details.sans {
                        println!("    • {}", san);
                    }
                }
                println!();
            } else {
                println!("\n╔═══════════════════════════════════════════════════════════════╗");
                println!("║  {:^61}  ║", format!("{} ({} certs)", title, cert_chain.len()));
                println!("╚═══════════════════════════════════════════════════════════════╝\n");
                
                for (idx, details) in cert_chain.iter().enumerate() {
                    let cert_type = if idx == 0 {
                        "Root Certificate"
                    } else if idx == cert_chain.len() - 1 {
                        "End-Entity Certificate"
                    } else {
                        "Intermediate Certificate"
                    };
                    
                    println!("┌─ Certificate #{} - {} ─────────────────────────", idx + 1, cert_type);
                    println!("│  CommonName: {}", details.common_name);
                    println!("│  Issuer: {}", details.issuer);
                    println!("│  Valid From: {}", details.not_before);
                    println!("│  Valid Until: {}", details.not_after);
                    
                    if !details.sans.is_empty() {
                        println!("│  SANs:");
                        for san in &details.sans {
                            println!("│    • {}", san);
                        }
                    }
                    println!("└────────────────────────────────────────────────────────────────\n");
                }
            }
        }
        Err(e) => {
            eprintln!("Error: Could not extract certificate details: {}", e);
        }
    }
}

fn main() -> Result<()> {
    // Load environment variables from .env
    let _ = dotenv();

    let cli = Cli::parse();

    match cli.command {
        Some(cmd) => execute_command(cmd, cli.debug),
        None => run_interactive_menu(cli.debug)
    }
}

fn execute_command(cmd: Commands, debug: bool) -> Result<()> {
    match cmd {
        Commands::Generate { conf, key, csr, password: pw } => {
            let pass = if let Some(p) = pw {
                p
            } else {
                password("Enter password for private key").interact()?
            };
            openssl_utils::generate_key_and_csr(&conf, &key, &csr, &pass)?;
            println!("Success: Generated {} and {}", key, csr);
        }
        Commands::Submit { csr, out, description, product_code } => {
            let config = sectigo::SectigoConfig::default();
            
            // If product_code not provided via CLI and not in env, prompt user to select
            let selected_code = if product_code.is_none() && std::env::var("SECTIGO_PRODUCT_CODE").is_err() {
                let profiles = sectigo::list_ssl_profiles(&config, debug)?;
                
                if profiles.is_empty() {
                    return Err(anyhow::anyhow!("No SSL profiles available"));
                }
                
                println!("\nAvailable SSL Certificate Types:");
                for (idx, profile) in profiles.iter().enumerate() {
                    println!("  {}. {} (ID: {})", idx + 1, profile.name, profile.id);
                }
                
                let selection: usize = input("Select certificate type number")
                    .interact()?;
                
                if selection < 1 || selection > profiles.len() {
                    return Err(anyhow::anyhow!("Invalid selection"));
                }
                
                Some(profiles[selection - 1].id.to_string())
            } else {
                product_code
            };
            
            let _cert_content = sectigo::enroll_and_collect(&config, &csr, &out, description, selected_code, debug)?;
            println!("Success: Certificate saved to {}", out);
        }
        Commands::Pfx {
            key,
            cert,
            out,
            chain,
        } => {
            println!("Note: If your private key is encrypted, you'll be prompted for its password.");
            println!("If not encrypted, just press Enter when prompted.");
            let key_pass: String = password("Enter password for private key (or press Enter if not encrypted)")
                .allow_empty()
                .interact()?;
            let key_pass_opt = if key_pass.is_empty() { None } else { Some(key_pass.as_str()) };
            
            let pfx_pass: String = password("Enter password for PFX export").interact()?;
            openssl_utils::create_pfx(&key, &cert, chain.as_deref(), &out, key_pass_opt, &pfx_pass)?;
            println!("Success: PFX created at {}", out);
        }
        Commands::Config {
            input: input_path,
            out,
            is_csr,
        } => {
            openssl_utils::generate_conf_from_cert_or_csr(&input_path, &out, is_csr)?;
            println!("Success: OpenSSL config written to {}", out);
        }
        Commands::ViewCert { input } => {
            let cert_content = std::fs::read_to_string(&input)?;
            display_cert_chain(&cert_content, "Certificate Details");
        }
        Commands::ViewCsr { input } => {
            println!("\n╔═══════════════════════════════════════════════════════════════╗");
            println!("║                        CSR Details                           ║");
            println!("╚═══════════════════════════════════════════════════════════════╝\n");
            
            match openssl_utils::extract_csr_details(&input) {
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
    }
    Ok(())
}

fn run_interactive_menu(debug: bool) -> Result<()> {
    intro("Cert Gen Tools")?;

    loop {
        let selection = select("What would you like to do?")
            .item(0, "Generate Key and CSR", "Build a new key and CSR from a config file")
            .item(1, "Submit CSR to Sectigo", "Submit existing CSR to Sectigo API")
            .item(2, "Create PFX", "Combine key and cert into a PFX file")
            .item(3, "Generate Config from Cert/CSR", "Create a .conf file from existing data")
            .item(4, "View Certificate Details", "Display details of an existing certificate")
            .item(5, "View CSR Details", "Display details of an existing CSR")
            .item(6, "List SSL Profiles", "View available SSL certificate types")
            .item(7, "Exit", "Close the application")
            .interact()?;

        match selection {
            0 => {
                let conf: String = input("Path to openssl.conf").interact()?;
                
                // Derive suggested paths from the config path
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
                openssl_utils::generate_key_and_csr(&conf, &key, &csr, &pass)?;
                println!("Success: Generated {} and {}", key, csr);
            }
            1 => {
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
                let desc_opt = if description.is_empty() { None } else { Some(description) };

                let config = sectigo::SectigoConfig::default();
                
                // If SECTIGO_PRODUCT_CODE not in env, prompt user to select
                let selected_code = if std::env::var("SECTIGO_PRODUCT_CODE").is_err() {
                    let profiles = sectigo::list_ssl_profiles(&config, debug)?;
                    
                    if profiles.is_empty() {
                        eprintln!("No SSL profiles available");
                        continue;
                    }
                    
                    let mut sel = select("Select SSL Certificate Type");
                    for (idx, profile) in profiles.iter().enumerate() {
                        sel = sel.item(idx, &profile.name, "");
                    }
                    let selection = sel.interact()?;
                    
                    Some(profiles[selection].id.to_string())
                } else {
                    None
                };
                
                // Extract and display CSR details before submitting
                println!("\n╔═══════════════════════════════════════════════════════════════╗");
                println!("║                    CSR Details Review                        ║");
                println!("╚═══════════════════════════════════════════════════════════════╝\n");
                
                match openssl_utils::extract_csr_details(&csr) {
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
                        
                        // Ask for confirmation
                        let confirm_result = confirm("Do you want to continue with enrollment?")
                            .interact()?;
                        
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
                
                let cert_content = sectigo::enroll_and_collect(&config, &csr, &out, desc_opt, selected_code, debug)?;
                
                // Display certificate details
                display_cert_chain(&cert_content, "Downloaded Certificate Details");
                
                println!("Success: Certificate saved to {}", out);
            }
            2 => {
                let key: String = input("Path to .key file").interact()?;
                let default_pfx = derive_path(&key, "pfx");

                let cert: String = input("Path to signed .crt file").interact()?;
                let chain: String = input("Path to chain file (optional)").required(false).interact()?;
                
                let out: String = if !default_pfx.is_empty() {
                    input("Path to output .pfx file")
                        .default_input(&default_pfx)
                        .interact()?
                } else {
                    input("Path to output .pfx file").interact()?
                };

                println!("Note: If your private key is encrypted, you'll be prompted for its password.");
                println!("If not encrypted, just press Enter when prompted.");
                let key_pass: String = password("Enter password for private key (or press Enter if not encrypted)")
                    .allow_empty()
                    .interact()?;
                let key_pass_opt = if key_pass.is_empty() { None } else { Some(key_pass.as_str()) };
                
                let pfx_pass: String = password("Enter password for PFX export").interact()?;
                let chain_opt = if chain.is_empty() { None } else { Some(chain.as_str()) };
                openssl_utils::create_pfx(&key, &cert, chain_opt, &out, key_pass_opt, &pfx_pass)?;
                println!("Success: PFX created at {}", out);
            }
            3 => {
                let input_path: String = input("Path to existing .cer or .csr").interact()?;
                let out: String = input("Path to output .conf file").interact()?;
                let is_csr = input_path.ends_with(".csr");
                openssl_utils::generate_conf_from_cert_or_csr(&input_path, &out, is_csr)?;
                println!("Success: OpenSSL config written to {}", out);
            }
            4 => {
                let input_path: String = input("Path to certificate file (.crt, .cer, .pem)").interact()?;
                
                match std::fs::read_to_string(&input_path) {
                    Ok(cert_content) => {
                        display_cert_chain(&cert_content, "Certificate Details");
                    }
                    Err(e) => {
                        eprintln!("Error reading file: {}", e);
                    }
                }
            }
            5 => {
                let input_path: String = input("Path to CSR file (.csr)").interact()?;
                
                println!("\n╔═══════════════════════════════════════════════════════════════╗");
                println!("║                        CSR Details                           ║");
                println!("╚═══════════════════════════════════════════════════════════════╝\n");
                
                match openssl_utils::extract_csr_details(&input_path) {
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
            6 => {
                let config = sectigo::SectigoConfig::default();
                match sectigo::list_ssl_profiles(&config, debug) {
                    Ok(profiles) => {
                        if profiles.is_empty() {
                            println!("\nNo SSL profiles available.");
                        } else {
                            println!("\n╔═══════════════════════════════════════════════════════════════╗");
                            println!("║              Available SSL Certificate Types                 ║");
                            println!("╚═══════════════════════════════════════════════════════════════╝\n");
                            
                            for profile in profiles {
                                println!("  • {} (ID: {})", profile.name, profile.id);
                                if !profile.terms.is_empty() {
                                    print!("    Available terms: ");
                                    let terms: Vec<String> = profile.terms.iter().map(|t| format!("{} days", t)).collect();
                                    println!("{}", terms.join(", "));
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

fn derive_path(base_path: &str, new_ext: &str) -> String {
    let path = Path::new(base_path);
    if let Some(stem) = path.file_stem() {
        let parent = path.parent().unwrap_or(Path::new(""));
        // Use Path::join to ensure OS-appropriate path separators
        let new_path = parent.join(format!("{}.{}", stem.to_string_lossy(), new_ext));
        return new_path.display().to_string();
    }
    String::new()
}

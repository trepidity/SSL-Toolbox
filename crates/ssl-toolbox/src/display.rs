use ssl_toolbox_core::{CertDetails, CertValidation, TlsCheckResult};

fn print_cert_detail_lines(prefix: &str, details: &CertDetails) {
    println!("{prefix}  CommonName: {}", details.common_name);
    println!("{prefix}  Issuer: {}", details.issuer);
    println!("{prefix}  Serial Number: {}", details.serial_number);
    println!(
        "{prefix}  Signature Algorithm: {}",
        details.signature_algorithm
    );
    println!("{prefix}  Public Key Bits: {}", details.public_key_bits);
    println!("{prefix}  Valid From: {}", details.not_before);
    println!("{prefix}  Valid Until: {}", details.not_after);
    println!("{prefix}  SHA1 Fingerprint: {}", details.sha1_fingerprint);
    println!(
        "{prefix}  SHA256 Fingerprint: {}",
        details.sha256_fingerprint
    );
}

/// Display certificate chain details from raw certificate file content.
pub fn display_cert_chain(cert_content: &[u8], title: &str) {
    match ssl_toolbox_core::x509_utils::extract_cert_chain_details(cert_content) {
        Ok(cert_chain) => {
            display_cert_details_list(&cert_chain, title);
        }
        Err(e) => {
            eprintln!("Error: Could not extract certificate details: {}", e);
        }
    }
}

/// Display a pre-parsed list of certificate details.
pub fn display_cert_details_list(cert_chain: &[CertDetails], title: &str) {
    if cert_chain.len() == 1 {
        println!("\n╔═══════════════════════════════════════════════════════════════╗");
        println!("║  {:^59}  ║", title);
        println!("╚═══════════════════════════════════════════════════════════════╝\n");

        let details = &cert_chain[0];
        print_cert_detail_lines("", details);

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
        println!(
            "║  {:^59}  ║",
            format!("{} ({} certs)", title, cert_chain.len())
        );
        println!("╚═══════════════════════════════════════════════════════════════╝\n");

        for (idx, details) in cert_chain.iter().enumerate() {
            let cert_type = if idx == 0 {
                "Leaf Certificate"
            } else if idx == cert_chain.len() - 1 {
                "Root / Top of Chain"
            } else {
                "Intermediate Certificate"
            };

            println!(
                "┌─ Certificate #{} - {} ─────────────────────────",
                idx + 1,
                cert_type
            );
            print_cert_detail_lines("│", details);

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

/// Display TLS check results with connection, version support, and certificate chain.
pub fn display_tls_check_result(result: &TlsCheckResult, label: &str) {
    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║  {:^59}  ║", label);
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    println!("  Endpoint: {}:{}", result.host, result.port);
    println!();

    // Negotiated connection info
    println!("┌─ Negotiated Connection ─────────────────────────────────────");
    println!("│  Protocol:     {}", result.cipher.protocol);
    println!("│  Cipher Suite: {}", result.cipher.name);
    println!("│  Cipher Bits:  {}", result.cipher.bits);
    println!("└────────────────────────────────────────────────────────────────\n");

    // TLS version support
    if !result.version_support.is_empty() {
        println!("┌─ TLS Version Support ───────────────────────────────────────");
        for probe in &result.version_support {
            let status = if probe.supported { "Yes" } else { "No" };
            let marker = if probe.supported { "+" } else { "-" };
            println!("│  [{}] {}: {}", marker, probe.label, status);
        }
        println!("└────────────────────────────────────────────────────────────────\n");
    }

    // Certificate validation
    if let Some(validation) = &result.validation {
        display_validation(validation);
    }

    // Certificate chain
    if result.cert_chain.is_empty() {
        println!("  No certificates presented by server.\n");
    } else {
        println!(
            "┌─ Certificate Chain ({} cert{}) ──────────────────────────────",
            result.cert_chain.len(),
            if result.cert_chain.len() == 1 {
                ""
            } else {
                "s"
            }
        );
        println!("│");

        for (idx, details) in result.cert_chain.iter().enumerate() {
            let cert_type = if idx == 0 {
                "Leaf Certificate"
            } else if idx == result.cert_chain.len() - 1 && result.cert_chain.len() > 1 {
                "Root / Top of Chain"
            } else {
                "Intermediate Certificate"
            };

            println!("│  ── Certificate #{} - {} ──", idx + 1, cert_type);
            println!("│     CommonName:  {}", details.common_name);
            println!("│     Issuer:      {}", details.issuer);
            println!("│     Valid From:  {}", details.not_before);
            println!("│     Valid Until: {}", details.not_after);

            if !details.sans.is_empty() {
                println!("│     SANs:");
                for san in &details.sans {
                    println!("│       • {}", san);
                }
            }

            if idx < result.cert_chain.len() - 1 {
                println!("│");
            }
        }
        println!("└────────────────────────────────────────────────────────────────\n");
    }
}

fn display_validation(validation: &CertValidation) {
    println!("┌─ Certificate Validation ────────────────────────────────────");

    if let Some(ref hostname) = validation.hostname_match {
        let marker = if hostname.passed { "+" } else { "-" };
        let label = if hostname.passed { "Pass" } else { "FAIL" };
        println!(
            "│  [{}] Hostname Match: {} ({})",
            marker, label, hostname.message
        );
    }

    if let Some(ref expiry) = validation.expiry_check {
        let marker = if expiry.passed { "+" } else { "-" };
        let label = if expiry.passed { "Pass" } else { "FAIL" };
        println!(
            "│  [{}] Expiry Check:   {} ({})",
            marker, label, expiry.message
        );
    }

    if let Some(ref chain) = validation.chain_valid {
        let marker = if chain.passed { "+" } else { "-" };
        let label = if chain.passed { "Pass" } else { "FAIL" };
        println!(
            "│  [{}] Chain Valid:     {} ({})",
            marker, label, chain.message
        );
    }

    println!("└────────────────────────────────────────────────────────────────\n");
}

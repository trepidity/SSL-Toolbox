use std::fmt::Write as _;

use ssl_toolbox_core::{
    CertDetails, CertValidation, PfxDetails, PrivateKeySummary, TlsCheckResult,
};

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

fn display_private_key_summary(summary: &PrivateKeySummary) {
    println!("┌─ Private Key ────────────────────────────────────────────────");
    println!(
        "│  Present:              {}",
        if summary.present { "Yes" } else { "No" }
    );
    if summary.present {
        println!("│  Key Algorithm:        {}", summary.algorithm);
        println!("│  Key Size:             {} bits", summary.key_size_bits);
        println!("│  Security Bits:        {}", summary.security_bits);
        println!(
            "│  Matches Leaf Cert:    {}",
            if summary.matches_leaf_certificate {
                "Yes"
            } else {
                "No"
            }
        );
    }
    println!("└────────────────────────────────────────────────────────────────\n");
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

/// Display PFX contents including the private-key summary.
pub fn display_pfx_details(details: &PfxDetails, title: &str) {
    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!(
        "║  {:^59}  ║",
        format!("{} ({} certs)", title, details.cert_chain.len())
    );
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    display_private_key_summary(&details.private_key);

    if details.cert_chain.len() == 1 {
        let cert = &details.cert_chain[0];
        print_cert_detail_lines("", cert);
        if cert.sans.is_empty() {
            println!("  SANs: None");
        } else {
            println!("  SANs:");
            for san in &cert.sans {
                println!("    • {}", san);
            }
        }
        println!();
        return;
    }

    for (idx, cert) in details.cert_chain.iter().enumerate() {
        let cert_type = if idx == 0 {
            "Leaf Certificate"
        } else if idx == details.cert_chain.len() - 1 {
            "Root / Top of Chain"
        } else {
            "Intermediate Certificate"
        };

        println!(
            "┌─ Certificate #{} - {} ─────────────────────────",
            idx + 1,
            cert_type
        );
        print_cert_detail_lines("│", cert);

        if cert.sans.is_empty() {
            println!("│  SANs: None");
        } else {
            println!("│  SANs:");
            for san in &cert.sans {
                println!("│    • {}", san);
            }
        }
        println!("└────────────────────────────────────────────────────────────────\n");
    }
}

/// Display TLS check results with connection, version support, and certificate chain.
pub fn display_tls_check_result(result: &TlsCheckResult, label: &str) {
    print!("{}", render_tls_check_result(result, label));
}

pub fn render_tls_check_result(result: &TlsCheckResult, label: &str) -> String {
    let mut output = String::new();

    writeln!(
        &mut output,
        "\n╔═══════════════════════════════════════════════════════════════╗"
    )
    .unwrap();
    writeln!(&mut output, "║  {:^59}  ║", label).unwrap();
    writeln!(
        &mut output,
        "╚═══════════════════════════════════════════════════════════════╝\n"
    )
    .unwrap();

    writeln!(&mut output, "  Endpoint: {}:{}", result.host, result.port).unwrap();
    writeln!(&mut output).unwrap();

    writeln!(
        &mut output,
        "┌─ Negotiated Connection ─────────────────────────────────────"
    )
    .unwrap();
    writeln!(&mut output, "│  Protocol:     {}", result.cipher.protocol).unwrap();
    writeln!(&mut output, "│  Cipher Suite: {}", result.cipher.name).unwrap();
    writeln!(&mut output, "│  Cipher Bits:  {}", result.cipher.bits).unwrap();
    writeln!(
        &mut output,
        "└────────────────────────────────────────────────────────────────\n"
    )
    .unwrap();

    if !result.version_support.is_empty() {
        writeln!(
            &mut output,
            "┌─ TLS Version Support ───────────────────────────────────────"
        )
        .unwrap();
        for probe in &result.version_support {
            let status = if probe.supported { "Yes" } else { "No" };
            let marker = if probe.supported { "+" } else { "-" };
            writeln!(&mut output, "│  [{}] {}: {}", marker, probe.label, status).unwrap();
        }
        writeln!(
            &mut output,
            "└────────────────────────────────────────────────────────────────\n"
        )
        .unwrap();
    }

    if !result.cipher_scan.is_empty() {
        writeln!(
            &mut output,
            "┌─ Full Protocol / Cipher Scan ───────────────────────────────"
        )
        .unwrap();
        for protocol in &result.cipher_scan {
            writeln!(
                &mut output,
                "│  {}: {}/{} locally testable cipher suite{} supported",
                protocol.protocol,
                protocol.supported_ciphers.len(),
                protocol.tested_cipher_count,
                if protocol.tested_cipher_count == 1 {
                    ""
                } else {
                    "s"
                }
            )
            .unwrap();

            if protocol.supported_ciphers.is_empty() {
                writeln!(&mut output, "│    None detected").unwrap();
            } else {
                for cipher in &protocol.supported_ciphers {
                    writeln!(&mut output, "│    • {} ({} bits)", cipher.name, cipher.bits).unwrap();
                }
            }
        }
        writeln!(
            &mut output,
            "└────────────────────────────────────────────────────────────────\n"
        )
        .unwrap();
    }

    if let Some(validation) = &result.validation {
        render_validation(validation, &mut output);
    }

    if result.cert_chain.is_empty() {
        writeln!(&mut output, "  No certificates presented by server.\n").unwrap();
    } else {
        writeln!(
            &mut output,
            "┌─ Certificate Chain ({} cert{}) ──────────────────────────────",
            result.cert_chain.len(),
            if result.cert_chain.len() == 1 {
                ""
            } else {
                "s"
            }
        )
        .unwrap();
        writeln!(&mut output, "│").unwrap();

        for (idx, details) in result.cert_chain.iter().enumerate() {
            let cert_type = if idx == 0 {
                "Leaf Certificate"
            } else if idx == result.cert_chain.len() - 1 && result.cert_chain.len() > 1 {
                "Root / Top of Chain"
            } else {
                "Intermediate Certificate"
            };

            writeln!(
                &mut output,
                "│  ── Certificate #{} - {} ──",
                idx + 1,
                cert_type
            )
            .unwrap();
            writeln!(&mut output, "│     CommonName:  {}", details.common_name).unwrap();
            writeln!(&mut output, "│     Issuer:      {}", details.issuer).unwrap();
            writeln!(&mut output, "│     Valid From:  {}", details.not_before).unwrap();
            writeln!(&mut output, "│     Valid Until: {}", details.not_after).unwrap();

            if !details.sans.is_empty() {
                writeln!(&mut output, "│     SANs:").unwrap();
                for san in &details.sans {
                    writeln!(&mut output, "│       • {}", san).unwrap();
                }
            }

            if idx < result.cert_chain.len() - 1 {
                writeln!(&mut output, "│").unwrap();
            }
        }
        writeln!(
            &mut output,
            "└────────────────────────────────────────────────────────────────\n"
        )
        .unwrap();
    }

    output
}

fn render_validation(validation: &CertValidation, output: &mut String) {
    writeln!(
        output,
        "┌─ Certificate Validation ────────────────────────────────────"
    )
    .unwrap();

    if let Some(ref hostname) = validation.hostname_match {
        let marker = if hostname.passed { "+" } else { "-" };
        let label = if hostname.passed { "Pass" } else { "FAIL" };
        writeln!(
            output,
            "│  [{}] Hostname Match: {} ({})",
            marker, label, hostname.message
        )
        .unwrap();
    }

    if let Some(ref expiry) = validation.expiry_check {
        let marker = if expiry.passed { "+" } else { "-" };
        let label = if expiry.passed { "Pass" } else { "FAIL" };
        writeln!(
            output,
            "│  [{}] Expiry Check:   {} ({})",
            marker, label, expiry.message
        )
        .unwrap();
    }

    if let Some(ref chain) = validation.chain_valid {
        let marker = if chain.passed { "+" } else { "-" };
        let label = if chain.passed { "Pass" } else { "FAIL" };
        writeln!(
            output,
            "│  [{}] Chain Valid:     {} ({})",
            marker, label, chain.message
        )
        .unwrap();
    }

    writeln!(
        output,
        "└────────────────────────────────────────────────────────────────\n"
    )
    .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssl_toolbox_core::{CipherInfo, TlsVersionProbeResult, ValidationResult};

    #[test]
    fn render_tls_check_result_includes_key_sections() {
        let result = TlsCheckResult {
            host: "example.com".to_string(),
            port: 443,
            cipher: CipherInfo {
                name: "TLS_AES_256_GCM_SHA384".to_string(),
                bits: 256,
                protocol: "TLSv1.3".to_string(),
            },
            cert_chain: vec![CertDetails {
                common_name: "example.com".to_string(),
                sans: vec!["example.com".to_string(), "www.example.com".to_string()],
                not_before: "2026-01-01T00:00:00Z".to_string(),
                not_after: "2027-01-01T00:00:00Z".to_string(),
                issuer: "Example Issuer".to_string(),
                signature_algorithm: "sha256WithRSAEncryption".to_string(),
                public_key_bits: 2048,
                serial_number: "01".to_string(),
                sha1_fingerprint: "sha1".to_string(),
                sha256_fingerprint: "sha256".to_string(),
            }],
            version_support: vec![TlsVersionProbeResult {
                label: "TLS 1.3".to_string(),
                supported: true,
            }],
            cipher_scan: vec![],
            validation: Some(CertValidation {
                hostname_match: Some(ValidationResult {
                    passed: true,
                    message: "matched".to_string(),
                }),
                expiry_check: None,
                chain_valid: None,
            }),
        };

        let rendered = render_tls_check_result(&result, "HTTPS Endpoint Verification");

        assert!(rendered.contains("HTTPS Endpoint Verification"));
        assert!(rendered.contains("Endpoint: example.com:443"));
        assert!(rendered.contains("TLS Version Support"));
        assert!(rendered.contains("Certificate Validation"));
        assert!(rendered.contains("Certificate Chain (1 cert)"));
    }
}

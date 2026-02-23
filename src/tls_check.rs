use crate::openssl_utils::CertDetails;
use anyhow::{Context, Result};
use openssl::nid::Nid;
use openssl::ssl::{SslConnector, SslMethod, SslRef, SslVerifyMode, SslVersion};
use openssl::x509::{X509Ref};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

pub struct CipherInfo {
    pub name: String,
    pub bits: i32,
    pub protocol: String,
}

pub struct TlsVersionProbeResult {
    pub label: String,
    pub supported: bool,
}

pub struct TlsCheckResult {
    pub host: String,
    pub port: u16,
    pub cipher: CipherInfo,
    pub cert_chain: Vec<CertDetails>,
    pub version_support: Vec<TlsVersionProbeResult>,
}

fn perform_tls_handshake(
    host: &str,
    port: u16,
    min_version: Option<SslVersion>,
    max_version: Option<SslVersion>,
) -> Result<openssl::ssl::SslStream<TcpStream>> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).context("Failed to create SSL connector")?;
    builder.set_verify(SslVerifyMode::NONE);

    if let Some(min) = min_version {
        builder
            .set_min_proto_version(Some(min))
            .context("Failed to set min TLS version")?;
    }
    if let Some(max) = max_version {
        builder
            .set_max_proto_version(Some(max))
            .context("Failed to set max TLS version")?;
    }

    let connector = builder.build();

    let addr = format!("{}:{}", host, port);
    let socket_addr = addr
        .to_socket_addrs()
        .context(format!("Failed to resolve {}", addr))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("No addresses found for {}", addr))?;

    let tcp = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))
        .context(format!("TCP connection to {} timed out", addr))?;

    // Also set read/write timeouts on the stream
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(10)))?;

    // Use the hostname for SNI (not IP address)
    let connect_host = if host.parse::<IpAddr>().is_ok() {
        // If the host is an IP, we still need to pass something for SNI
        // but SNI won't actually be sent for IPs
        host
    } else {
        host
    };

    let ssl_stream = connector
        .connect(connect_host, tcp)
        .context(format!("TLS handshake with {} failed", addr))?;

    Ok(ssl_stream)
}

fn x509_to_cert_details(cert: &X509Ref) -> CertDetails {
    let subject = cert.subject_name();
    let common_name = subject
        .entries()
        .find(|entry| entry.object().nid() == Nid::COMMONNAME)
        .and_then(|entry| entry.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "N/A".to_string());

    let mut sans = Vec::new();
    if let Some(san_ext) = cert.subject_alt_names() {
        for n in san_ext {
            if let Some(dns) = n.dnsname() {
                sans.push(format!("DNS: {}", dns));
            } else if let Some(ip) = n.ipaddress() {
                let addr = match ip.len() {
                    4 => IpAddr::V4(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
                    16 => {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(ip);
                        IpAddr::V6(std::net::Ipv6Addr::from(octets))
                    }
                    _ => continue,
                };
                sans.push(format!("IP: {}", addr));
            } else if let Some(email) = n.email() {
                sans.push(format!("Email: {}", email));
            } else if let Some(uri) = n.uri() {
                sans.push(format!("URI: {}", uri));
            }
        }
    }

    let not_before = cert.not_before().to_string();
    let not_after = cert.not_after().to_string();

    let issuer = cert.issuer_name();
    let issuer_cn = issuer
        .entries()
        .find(|entry| entry.object().nid() == Nid::COMMONNAME)
        .and_then(|entry| entry.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            issuer
                .entries()
                .find(|entry| entry.object().nid() == Nid::ORGANIZATIONNAME)
                .and_then(|entry| entry.data().as_utf8().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "Unknown".to_string())
        });

    CertDetails {
        common_name,
        sans,
        not_before,
        not_after,
        issuer: issuer_cn,
    }
}

fn extract_chain_from_ssl(ssl: &SslRef) -> Vec<CertDetails> {
    let mut chain = Vec::new();
    if let Some(cert_stack) = ssl.peer_cert_chain() {
        for cert in cert_stack {
            chain.push(x509_to_cert_details(cert));
        }
    }
    chain
}

fn probe_tls_versions(host: &str, port: u16) -> Vec<TlsVersionProbeResult> {
    let versions = vec![
        ("TLS 1.0", SslVersion::TLS1),
        ("TLS 1.1", SslVersion::TLS1_1),
        ("TLS 1.2", SslVersion::TLS1_2),
        ("TLS 1.3", SslVersion::TLS1_3),
    ];

    let mut results = Vec::new();
    for (label, version) in versions {
        let supported = perform_tls_handshake(host, port, Some(version), Some(version)).is_ok();
        results.push(TlsVersionProbeResult {
            label: label.to_string(),
            supported,
        });
    }
    results
}

pub fn connect_and_check(host: &str, port: u16) -> Result<TlsCheckResult> {
    // Default handshake (let OpenSSL negotiate best available)
    let ssl_stream =
        perform_tls_handshake(host, port, None, None).context("Failed to connect to endpoint")?;

    let ssl = ssl_stream.ssl();

    // Extract cipher info
    let cipher = if let Some(current) = ssl.current_cipher() {
        CipherInfo {
            name: current.name().to_string(),
            bits: current.bits().secret,
            protocol: ssl.version_str().to_string(),
        }
    } else {
        CipherInfo {
            name: "Unknown".to_string(),
            bits: 0,
            protocol: ssl.version_str().to_string(),
        }
    };

    // Extract certificate chain
    let cert_chain = extract_chain_from_ssl(ssl);

    // Probe individual TLS versions
    let version_support = probe_tls_versions(host, port);

    Ok(TlsCheckResult {
        host: host.to_string(),
        port,
        cipher,
        cert_chain,
        version_support,
    })
}

pub fn display_tls_check_result(result: &TlsCheckResult, label: &str) {
    println!(
        "\n╔═══════════════════════════════════════════════════════════════╗"
    );
    println!("║  {:^59}  ║", label);
    println!(
        "╚═══════════════════════════════════════════════════════════════╝\n"
    );

    println!("  Endpoint: {}:{}", result.host, result.port);
    println!();

    // Negotiated connection info
    println!("┌─ Negotiated Connection ─────────────────────────────────────");
    println!("│  Protocol:     {}", result.cipher.protocol);
    println!("│  Cipher Suite: {}", result.cipher.name);
    println!("│  Cipher Bits:  {}", result.cipher.bits);
    println!(
        "└────────────────────────────────────────────────────────────────\n"
    );

    // TLS version support
    println!("┌─ TLS Version Support ───────────────────────────────────────");
    for probe in &result.version_support {
        let status = if probe.supported { "Yes" } else { "No" };
        let marker = if probe.supported { "+" } else { "-" };
        println!("│  [{}] {}: {}", marker, probe.label, status);
    }
    println!(
        "└────────────────────────────────────────────────────────────────\n"
    );

    // Certificate chain
    if result.cert_chain.is_empty() {
        println!("  No certificates presented by server.\n");
    } else {
        println!(
            "┌─ Certificate Chain ({} cert{}) ──────────────────────────────",
            result.cert_chain.len(),
            if result.cert_chain.len() == 1 { "" } else { "s" }
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
        println!(
            "└────────────────────────────────────────────────────────────────\n"
        );
    }
}

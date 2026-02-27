use anyhow::{Context, Result};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::validation::validate_peer_cert;
use crate::x509_utils::extract_chain_from_ssl;
use crate::{CipherInfo, TlsCheckResult, TlsVersionProbeResult};

/// Perform a TLS handshake with specified version constraints.
/// Returns the SSL stream on success.
pub fn perform_tls_handshake(
    host: &str,
    port: u16,
    min_version: Option<SslVersion>,
    max_version: Option<SslVersion>,
    verify: bool,
) -> Result<openssl::ssl::SslStream<TcpStream>> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).context("Failed to create SSL connector")?;

    if !verify {
        builder.set_verify(SslVerifyMode::NONE);
    }

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

    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(10)))?;

    let connect_host = if host.parse::<IpAddr>().is_ok() {
        host
    } else {
        host
    };

    let ssl_stream = connector
        .connect(connect_host, tcp)
        .context(format!("TLS handshake with {} failed", addr))?;

    Ok(ssl_stream)
}

/// Probe which TLS versions the server supports.
pub fn probe_tls_versions(host: &str, port: u16) -> Vec<TlsVersionProbeResult> {
    let versions = vec![
        ("TLS 1.0", SslVersion::TLS1),
        ("TLS 1.1", SslVersion::TLS1_1),
        ("TLS 1.2", SslVersion::TLS1_2),
        ("TLS 1.3", SslVersion::TLS1_3),
    ];

    let mut results = Vec::new();
    for (label, version) in versions {
        let supported =
            perform_tls_handshake(host, port, Some(version), Some(version), false).is_ok();
        results.push(TlsVersionProbeResult {
            label: label.to_string(),
            supported,
        });
    }
    results
}

/// Connect to a TLS endpoint, extract cipher/cert/version info, and optionally validate.
pub fn connect_and_check(host: &str, port: u16, verify: bool) -> Result<TlsCheckResult> {
    // Default handshake (let OpenSSL negotiate best available)
    // Always connect without verification for probing; we do validation separately
    let ssl_stream = perform_tls_handshake(host, port, None, None, false)
        .context("Failed to connect to endpoint")?;

    let ssl = ssl_stream.ssl();

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

    let cert_chain = extract_chain_from_ssl(ssl);

    let validation = if verify {
        Some(validate_peer_cert(ssl, host))
    } else {
        None
    };

    let version_support = probe_tls_versions(host, port);

    Ok(TlsCheckResult {
        host: host.to_string(),
        port,
        cipher,
        cert_chain,
        version_support,
        validation,
    })
}

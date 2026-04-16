use anyhow::{Context, Result};
use openssl::ssl::{SslCipherRef, SslConnector, SslMethod, SslRef, SslVerifyMode, SslVersion};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::validation::validate_peer_cert;
use crate::x509_utils::extract_chain_from_ssl;
use crate::{CipherInfo, TlsCheckResult, TlsCipherScanResult, TlsVersionProbeResult};

const TLS10_TLS11_CIPHERS: &[&str] = &[
    "ECDHE-ECDSA-AES256-SHA",
    "ECDHE-RSA-AES256-SHA",
    "DHE-RSA-AES256-SHA",
    "DHE-DSS-AES256-SHA",
    "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-RSA-AES128-SHA",
    "DHE-RSA-AES128-SHA",
    "DHE-DSS-AES128-SHA",
    "AES256-SHA",
    "AES128-SHA",
    "DES-CBC3-SHA",
];

const TLS12_CIPHERS: &[&str] = &[
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-DSS-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-DSS-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-RSA-AES256-SHA384",
    "DHE-RSA-AES256-SHA256",
    "DHE-DSS-AES256-SHA256",
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-RSA-AES128-SHA256",
    "DHE-RSA-AES128-SHA256",
    "DHE-DSS-AES128-SHA256",
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "AES256-SHA256",
    "AES128-SHA256",
    "AES256-SHA",
    "AES128-SHA",
    "DES-CBC3-SHA",
];

const TLS13_CIPHERS: &[&str] = &[
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
];

#[derive(Clone, Copy)]
struct ProtocolScanProfile {
    label: &'static str,
    version: SslVersion,
    ciphers: &'static [&'static str],
    is_tls13: bool,
}

/// Perform a TLS handshake with specified version constraints.
/// Returns the SSL stream on success.
pub fn perform_tls_handshake(
    host: &str,
    port: u16,
    min_version: Option<SslVersion>,
    max_version: Option<SslVersion>,
    verify: bool,
) -> Result<openssl::ssl::SslStream<TcpStream>> {
    perform_tls_handshake_with_cipher_override(host, port, min_version, max_version, verify, None)
}

fn perform_tls_handshake_with_cipher_override(
    host: &str,
    port: u16,
    min_version: Option<SslVersion>,
    max_version: Option<SslVersion>,
    verify: bool,
    cipher_override: Option<(&str, bool)>,
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

    if let Some((cipher, is_tls13)) = cipher_override {
        if is_tls13 {
            builder
                .set_ciphersuites(cipher)
                .context("Failed to set TLS 1.3 cipher suite")?;
        } else {
            builder
                .set_cipher_list(cipher)
                .context("Failed to set TLS cipher suite")?;
        }
    }

    let connector = builder.build();

    let addr = socket_addr_target(host, port);
    let socket_addr = addr
        .to_socket_addrs()
        .context(format!("Failed to resolve {}", addr))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("No addresses found for {}", addr))?;

    let tcp = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))
        .context(format!("TCP connection to {} timed out", addr))?;

    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(10)))?;

    let connect_host = host.trim_matches(|ch| ch == '[' || ch == ']');

    let ssl_stream = connector
        .connect(connect_host, tcp)
        .context(format!("TLS handshake with {} failed", addr))?;

    Ok(ssl_stream)
}

fn socket_addr_target(host: &str, port: u16) -> String {
    let host = host.trim_matches(|ch| ch == '[' || ch == ']');
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Probe which TLS versions the server supports.
pub fn probe_tls_versions(host: &str, port: u16) -> Vec<TlsVersionProbeResult> {
    let mut results = Vec::new();
    for profile in protocol_scan_profiles() {
        let supported = perform_tls_handshake(
            host,
            port,
            Some(profile.version),
            Some(profile.version),
            false,
        )
        .is_ok();
        results.push(TlsVersionProbeResult {
            label: profile.label.to_string(),
            supported,
        });
    }
    results
}

/// Connect to a TLS endpoint, extract cipher/cert/version info, and optionally validate.
pub fn connect_and_check(
    host: &str,
    port: u16,
    verify: bool,
    full_scan: bool,
) -> Result<TlsCheckResult> {
    // Default handshake (let OpenSSL negotiate best available)
    // Always connect without verification for probing; we do validation separately
    let ssl_stream = perform_tls_handshake(host, port, None, None, false)
        .context("Failed to connect to endpoint")?;

    let ssl = ssl_stream.ssl();
    let cipher = current_cipher_info(ssl);

    let cert_chain = extract_chain_from_ssl(ssl);

    let validation = if verify {
        Some(validate_peer_cert(ssl, host))
    } else {
        None
    };

    let version_support = probe_tls_versions(host, port);
    let cipher_scan = if full_scan {
        probe_protocol_cipher_support(host, port, &version_support)
    } else {
        Vec::new()
    };

    Ok(TlsCheckResult {
        host: host.to_string(),
        port,
        cipher,
        cert_chain,
        version_support,
        cipher_scan,
        validation,
    })
}

fn protocol_scan_profiles() -> Vec<ProtocolScanProfile> {
    vec![
        ProtocolScanProfile {
            label: "TLS 1.0",
            version: SslVersion::TLS1,
            ciphers: TLS10_TLS11_CIPHERS,
            is_tls13: false,
        },
        ProtocolScanProfile {
            label: "TLS 1.1",
            version: SslVersion::TLS1_1,
            ciphers: TLS10_TLS11_CIPHERS,
            is_tls13: false,
        },
        ProtocolScanProfile {
            label: "TLS 1.2",
            version: SslVersion::TLS1_2,
            ciphers: TLS12_CIPHERS,
            is_tls13: false,
        },
        ProtocolScanProfile {
            label: "TLS 1.3",
            version: SslVersion::TLS1_3,
            ciphers: TLS13_CIPHERS,
            is_tls13: true,
        },
    ]
}

fn current_cipher_info(ssl: &SslRef) -> CipherInfo {
    if let Some(current) = ssl.current_cipher() {
        cipher_info_from_ref(ssl, current)
    } else {
        CipherInfo {
            name: "Unknown".to_string(),
            bits: 0,
            protocol: ssl.version_str().to_string(),
        }
    }
}

fn cipher_info_from_ref(ssl: &SslRef, cipher: &SslCipherRef) -> CipherInfo {
    let name = cipher
        .standard_name()
        .unwrap_or_else(|| cipher.name())
        .to_string();

    CipherInfo {
        name,
        bits: cipher.bits().secret,
        protocol: ssl.version_str().to_string(),
    }
}

fn locally_testable_cipher_count(ciphers: &[&str], is_tls13: bool) -> usize {
    ciphers
        .iter()
        .copied()
        .filter(|cipher| cipher_is_locally_supported(cipher, is_tls13))
        .count()
}

fn cipher_is_locally_supported(cipher: &str, is_tls13: bool) -> bool {
    let Ok(mut builder) = SslConnector::builder(SslMethod::tls()) else {
        return false;
    };

    if is_tls13 {
        builder.set_ciphersuites(cipher).is_ok()
    } else {
        builder.set_cipher_list(cipher).is_ok()
    }
}

fn probe_protocol_cipher_support(
    host: &str,
    port: u16,
    version_support: &[TlsVersionProbeResult],
) -> Vec<TlsCipherScanResult> {
    let mut results = Vec::new();

    for profile in protocol_scan_profiles() {
        let tested_cipher_count = locally_testable_cipher_count(profile.ciphers, profile.is_tls13);
        let protocol_supported = version_support
            .iter()
            .find(|probe| probe.label == profile.label)
            .map(|probe| probe.supported)
            .unwrap_or(false);

        let mut supported_ciphers = Vec::new();
        if protocol_supported {
            for cipher in profile.ciphers {
                if !cipher_is_locally_supported(cipher, profile.is_tls13) {
                    continue;
                }

                let handshake = perform_tls_handshake_with_cipher_override(
                    host,
                    port,
                    Some(profile.version),
                    Some(profile.version),
                    false,
                    Some((cipher, profile.is_tls13)),
                );

                if let Ok(ssl_stream) = handshake {
                    supported_ciphers.push(current_cipher_info(ssl_stream.ssl()));
                }
            }
        }

        results.push(TlsCipherScanResult {
            protocol: profile.label.to_string(),
            tested_cipher_count,
            supported_ciphers,
        });
    }

    results
}

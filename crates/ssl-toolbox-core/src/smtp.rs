use anyhow::{Context, Result};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::validation::validate_peer_cert;
use crate::x509_utils::extract_chain_from_ssl;
use crate::{CipherInfo, TlsCheckResult};

/// Read lines from the SMTP server until we get a line where the 4th char is a space
/// (indicating end of multi-line response), or a single-line response.
fn read_smtp_response(reader: &mut BufReader<&TcpStream>) -> Result<String> {
    let mut full_response = String::new();
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .context("Failed to read SMTP response")?;
        if line.is_empty() {
            break;
        }
        full_response.push_str(&line);
        // SMTP multi-line responses use "NNN-" continuation, final line uses "NNN "
        if line.len() >= 4 && line.as_bytes()[3] == b' ' {
            break;
        }
    }
    Ok(full_response)
}

/// Connect to an SMTP server, perform STARTTLS upgrade, and check the TLS certificate.
pub fn connect_and_check_smtp(
    host: &str,
    port: u16,
    verify: bool,
) -> Result<TlsCheckResult> {
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

    // Read 220 greeting
    let mut reader = BufReader::new(&tcp);
    let greeting = read_smtp_response(&mut reader)?;
    if !greeting.starts_with("220") {
        return Err(anyhow::anyhow!(
            "Expected 220 greeting, got: {}",
            greeting.trim()
        ));
    }

    // Send EHLO
    (&tcp).write_all(b"EHLO ssl-toolbox\r\n")?;
    (&tcp).flush()?;
    let ehlo_response = read_smtp_response(&mut reader)?;
    if !ehlo_response.starts_with("250") {
        return Err(anyhow::anyhow!(
            "EHLO failed: {}",
            ehlo_response.trim()
        ));
    }

    // Check STARTTLS support
    let has_starttls = ehlo_response
        .lines()
        .any(|line| line.to_uppercase().contains("STARTTLS"));
    if !has_starttls {
        return Err(anyhow::anyhow!(
            "Server does not advertise STARTTLS capability"
        ));
    }

    // Send STARTTLS
    (&tcp).write_all(b"STARTTLS\r\n")?;
    (&tcp).flush()?;
    let starttls_response = read_smtp_response(&mut reader)?;
    if !starttls_response.starts_with("220") {
        return Err(anyhow::anyhow!(
            "STARTTLS failed: {}",
            starttls_response.trim()
        ));
    }

    // Upgrade to TLS
    let mut ssl_builder =
        SslConnector::builder(SslMethod::tls()).context("Failed to create SSL connector")?;
    ssl_builder.set_verify(SslVerifyMode::NONE);
    let connector = ssl_builder.build();

    let ssl_stream = connector
        .connect(host, tcp)
        .context("TLS handshake after STARTTLS failed")?;

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

    // SMTP STARTTLS doesn't easily support TLS version probing
    // (would need to reconnect and redo the SMTP handshake for each version)
    let version_support = Vec::new();

    Ok(TlsCheckResult {
        host: host.to_string(),
        port,
        cipher,
        cert_chain,
        version_support,
        validation,
    })
}

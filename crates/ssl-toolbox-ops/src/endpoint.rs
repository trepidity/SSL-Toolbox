//! Endpoint target parsing and certificate-chain export.
//!
//! Users paste whatever they have — a bare hostname, a full URL, a
//! `host:port` pair, a bracketed IPv6 literal. This module normalizes all of
//! it to a `(host, port)` pair so no front-end has to re-implement the rules.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use ssl_toolbox_core::TlsCheckResult;

/// Which protocol a verification target speaks.
///
/// The TLS handshake is identical across all three; the protocol only selects
/// the default port, how the session is established (direct vs. STARTTLS), and
/// which follow-up probes are available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointProtocol {
    Https,
    Ldaps,
    Smtp,
}

impl EndpointProtocol {
    pub fn default_port(self) -> u16 {
        match self {
            Self::Https => 443,
            Self::Ldaps => 636,
            Self::Smtp => 25,
        }
    }

    pub fn report_title(self) -> &'static str {
        match self {
            Self::Https => "HTTPS Endpoint Verification",
            Self::Ldaps => "LDAPS Endpoint Verification",
            Self::Smtp => "SMTP STARTTLS Endpoint Verification",
        }
    }

    /// SMTP negotiates TLS via STARTTLS after a plaintext greeting, so it
    /// cannot participate in the direct-handshake cipher scan.
    pub fn supports_full_scan(self) -> bool {
        !matches!(self, Self::Smtp)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEndpointInput {
    pub host: String,
    pub port: Option<u16>,
}

/// Resolve a raw host string plus an explicit port into a concrete target.
///
/// An explicit port that differs from the protocol default always wins; a port
/// embedded in the input is only honored when the caller left the port at its
/// default, so `--port` on the CLI still overrides `host:port` text.
pub fn normalize_target(raw_host: &str, port: u16, default_port: u16) -> Result<(String, u16)> {
    let parsed = parse_endpoint_input(raw_host)?;
    let effective_port = if port == default_port {
        parsed.port.unwrap_or(port)
    } else {
        port
    };
    Ok((parsed.host, effective_port))
}

pub fn parse_endpoint_input(raw: &str) -> Result<ParsedEndpointInput> {
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

/// Bare IPv6 literals need brackets before they can be shown as a target.
pub fn format_connect_target(host: &str) -> std::borrow::Cow<'_, str> {
    if host.contains(':') && !host.starts_with('[') {
        std::borrow::Cow::Owned(format!("[{host}]"))
    } else {
        std::borrow::Cow::Borrowed(host)
    }
}

pub fn default_certificate_export_dir(host: &str, port: u16) -> String {
    format!("{}-{}-certs", sanitize_filename_component(host), port)
}

/// Write each certificate the server presented to its own PEM file.
///
/// Files are numbered in path order (leaf first) so the on-disk ordering
/// matches the chain as reconstructed, not as the server happened to send it.
pub fn export_cert_chain_pem(result: &TlsCheckResult, dir: &Path) -> Result<Vec<PathBuf>> {
    if result.cert_chain_pem.is_empty() {
        return Ok(Vec::new());
    }

    std::fs::create_dir_all(dir).with_context(|| {
        format!(
            "Failed to create certificate export directory {}",
            dir.display()
        )
    })?;

    let host = sanitize_filename_component(&result.host);
    let mut exported = Vec::new();
    for (idx, pem) in result.cert_chain_pem.iter().enumerate() {
        let role = certificate_export_role(idx, result.cert_chain_pem.len());
        let path = dir.join(format!(
            "{}-{}-cert-{:02}-{}.pem",
            host,
            result.port,
            idx + 1,
            role
        ));
        std::fs::write(&path, pem.as_bytes())
            .with_context(|| format!("Failed to write certificate PEM to {}", path.display()))?;
        exported.push(path);
    }

    Ok(exported)
}

pub fn certificate_export_role(idx: usize, len: usize) -> &'static str {
    if len == 1 {
        "certificate"
    } else if idx == 0 {
        "leaf"
    } else {
        "chain"
    }
}

pub fn sanitize_filename_component(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches(['.', '-', '_'])
        .to_string();

    if sanitized.is_empty() {
        "host".to_string()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // L2 — hand-written parser over untrusted input (ARCHITECTURE.md §2.7).
    // Users paste URLs, bare hosts, and IPv6 literals interchangeably; a
    // mis-parse silently verifies the wrong endpoint and reports it as healthy.

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
    fn normalize_target_uses_embedded_port_when_default_was_requested() {
        let normalized =
            normalize_target("ldaps://ldap.example.com:1636/ou=People", 636, 636)
                .expect("normalized target");

        assert_eq!(normalized, ("ldap.example.com".to_string(), 1636));
    }

    #[test]
    fn normalize_target_preserves_explicit_non_default_port() {
        let normalized =
            normalize_target("https://example.com:8443", 9443, 443).expect("normalized target");

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
    fn export_cert_chain_pem_writes_one_file_per_returned_cert() {
        let dir =
            std::env::temp_dir().join(format!("ssl-toolbox-export-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let result = ssl_toolbox_core::TlsCheckResult {
            host: "example.com".to_string(),
            port: 443,
            cipher: ssl_toolbox_core::CipherInfo {
                name: "TLS_AES_256_GCM_SHA384".to_string(),
                bits: 256,
                protocol: "TLSv1.3".to_string(),
            },
            cert_chain: Vec::new(),
            cert_chain_pem: vec![
                "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n".to_string(),
                "-----BEGIN CERTIFICATE-----\nissuer\n-----END CERTIFICATE-----\n".to_string(),
            ],
            version_support: Vec::new(),
            cipher_scan: Vec::new(),
            validation: None,
            chain_sent_out_of_order: false,
        };

        let exported = export_cert_chain_pem(&result, &dir).expect("exported certs");

        assert_eq!(exported.len(), 2);
        assert_eq!(
            exported[0].file_name().and_then(|name| name.to_str()),
            Some("example.com-443-cert-01-leaf.pem")
        );
        assert_eq!(
            exported[1].file_name().and_then(|name| name.to_str()),
            Some("example.com-443-cert-02-chain.pem")
        );
        assert_eq!(
            std::fs::read_to_string(&exported[0]).expect("leaf file"),
            result.cert_chain_pem[0]
        );
        assert_eq!(
            std::fs::read_to_string(&exported[1]).expect("chain file"),
            result.cert_chain_pem[1]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn certificate_export_default_dir_sanitizes_hostnames() {
        assert_eq!(
            default_certificate_export_dir("[2001:db8::1]", 443),
            "2001_db8__1-443-certs"
        );
    }
}

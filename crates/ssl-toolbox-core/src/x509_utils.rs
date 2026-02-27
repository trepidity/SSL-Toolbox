use anyhow::{Context, Result};
use openssl::nid::Nid;
use openssl::ssl::SslRef;
use openssl::x509::{X509, X509Ref};
use std::net::IpAddr;

use crate::CertDetails;

/// Extract SANs from an X509 certificate into a formatted string list.
pub fn extract_sans(cert: &X509Ref) -> Vec<String> {
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
    sans
}

/// Extract the issuer CN (or Organization as fallback) from an X509 certificate.
fn extract_issuer_cn(cert: &X509Ref) -> String {
    let issuer = cert.issuer_name();
    issuer
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
        })
}

/// Convert an X509Ref to a CertDetails struct. Single canonical implementation.
pub fn x509_to_cert_details(cert: &X509Ref) -> CertDetails {
    let subject = cert.subject_name();
    let common_name = subject
        .entries()
        .find(|entry| entry.object().nid() == Nid::COMMONNAME)
        .and_then(|entry| entry.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "N/A".to_string());

    let sans = extract_sans(cert);
    let not_before = cert.not_before().to_string();
    let not_after = cert.not_after().to_string();
    let issuer_cn = extract_issuer_cn(cert);

    CertDetails {
        common_name,
        sans,
        not_before,
        not_after,
        issuer: issuer_cn,
    }
}

/// Extract certificate chain details from the SSL connection.
pub fn extract_chain_from_ssl(ssl: &SslRef) -> Vec<CertDetails> {
    let mut chain = Vec::new();
    if let Some(cert_stack) = ssl.peer_cert_chain() {
        for cert in cert_stack {
            chain.push(x509_to_cert_details(cert));
        }
    }
    chain
}

/// Parse a certificate file (PEM or DER) and return ordered chain details.
pub fn extract_cert_chain_details(cert_file_content: &[u8]) -> Result<Vec<CertDetails>> {
    let all_certs = X509::stack_from_pem(cert_file_content)
        .or_else(|_| X509::from_der(cert_file_content).map(|cert| vec![cert]))
        .context("Failed to parse certificate file (tried PEM and DER)")?;

    if all_certs.is_empty() {
        return Err(anyhow::anyhow!("No certificates found in file"));
    }

    let get_subject_cn = |cert: &X509| -> String {
        cert.subject_name()
            .entries()
            .find(|entry| entry.object().nid() == Nid::COMMONNAME)
            .and_then(|entry| entry.data().as_utf8().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "N/A".to_string())
    };

    let get_issuer_cn = |cert: &X509| -> String {
        cert.issuer_name()
            .entries()
            .find(|entry| entry.object().nid() == Nid::COMMONNAME)
            .and_then(|entry| entry.data().as_utf8().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                cert.issuer_name()
                    .entries()
                    .find(|entry| entry.object().nid() == Nid::ORGANIZATIONNAME)
                    .and_then(|entry| entry.data().as_utf8().ok())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Unknown".to_string())
            })
    };

    // Build ordered chain starting from root
    let root_cert = all_certs.iter().find(|cert| {
        let subject_cn = get_subject_cn(cert);
        let issuer_cn = get_issuer_cn(cert);
        subject_cn == issuer_cn
    });

    let mut ordered_certs = Vec::new();

    if let Some(root) = root_cert {
        ordered_certs.push(root);

        let mut current_subject = get_subject_cn(root);

        while ordered_certs.len() < all_certs.len() {
            let next_cert = all_certs.iter().find(|cert| {
                let issuer_cn = get_issuer_cn(cert);
                let subject_cn = get_subject_cn(cert);
                issuer_cn == current_subject && subject_cn != current_subject
            });

            if let Some(next) = next_cert {
                ordered_certs.push(next);
                current_subject = get_subject_cn(next);
            } else {
                break;
            }
        }

        // Add any remaining certs not yet in the ordered list
        for cert in &all_certs {
            if !ordered_certs.iter().any(|c| std::ptr::eq(*c, cert)) {
                ordered_certs.push(cert);
            }
        }
    } else {
        for cert in &all_certs {
            ordered_certs.push(cert);
        }
    }

    let cert_details_list = ordered_certs
        .iter()
        .map(|cert| x509_to_cert_details(cert))
        .collect();

    Ok(cert_details_list)
}

/// Parse a single PEM certificate and return its details.
pub fn extract_cert_details(cert_content: &str) -> Result<CertDetails> {
    let cert = X509::from_pem(cert_content.as_bytes()).context("Failed to parse certificate")?;
    Ok(x509_to_cert_details(&cert))
}

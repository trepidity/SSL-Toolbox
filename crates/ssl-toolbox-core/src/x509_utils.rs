use anyhow::{Context, Result};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::ssl::SslRef;
use openssl::x509::{X509, X509Ref};
use std::collections::HashSet;
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

fn extract_signature_algorithm(cert: &X509Ref) -> String {
    cert.signature_algorithm()
        .object()
        .nid()
        .long_name()
        .ok()
        .unwrap_or("Unknown")
        .to_string()
}

fn extract_public_key_bits(cert: &X509Ref) -> u32 {
    cert.public_key().map(|key| key.bits()).unwrap_or(0)
}

fn extract_serial_number(cert: &X509Ref) -> String {
    cert.serial_number()
        .to_bn()
        .ok()
        .and_then(|bn| bn.to_hex_str().ok().map(|serial| serial.to_string()))
        .unwrap_or_else(|| "Unknown".to_string())
}

fn format_fingerprint(cert: &X509Ref, digest: MessageDigest) -> String {
    cert.digest(digest)
        .ok()
        .map(|bytes| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(":")
        })
        .unwrap_or_else(|| "Unknown".to_string())
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
    let signature_algorithm = extract_signature_algorithm(cert);
    let public_key_bits = extract_public_key_bits(cert);
    let serial_number = extract_serial_number(cert);
    let sha1_fingerprint = format_fingerprint(cert, MessageDigest::sha1());
    let sha256_fingerprint = format_fingerprint(cert, MessageDigest::sha256());

    CertDetails {
        common_name,
        sans,
        not_before,
        not_after,
        issuer: issuer_cn,
        signature_algorithm,
        public_key_bits,
        serial_number,
        sha1_fingerprint,
        sha256_fingerprint,
    }
}

fn push_unique_cert(cert: &X509Ref, chain: &mut Vec<X509>, seen: &mut HashSet<Vec<u8>>) {
    let Ok(der) = cert.to_der() else {
        return;
    };

    if !seen.insert(der.clone()) {
        return;
    }

    if let Ok(owned) = X509::from_der(&der) {
        chain.push(owned);
    }
}

fn build_peer_chain<'a, I>(leaf: Option<&'a X509Ref>, peer_chain: I) -> Vec<X509>
where
    I: IntoIterator<Item = &'a X509Ref>,
{
    let mut chain = Vec::new();
    let mut seen = HashSet::new();

    if let Some(leaf) = leaf {
        push_unique_cert(leaf, &mut chain, &mut seen);
    }

    for cert in peer_chain {
        push_unique_cert(cert, &mut chain, &mut seen);
    }

    chain
}

/// Collect the peer chain in leaf-first order with duplicate certificates removed.
pub fn collect_peer_chain(ssl: &SslRef) -> Vec<X509> {
    let leaf = ssl.peer_certificate();

    match ssl.peer_cert_chain() {
        Some(cert_stack) => {
            build_peer_chain(leaf.as_ref().map(|cert| cert.as_ref()), cert_stack.iter())
        }
        None => build_peer_chain(leaf.as_ref().map(|cert| cert.as_ref()), std::iter::empty()),
    }
}

/// Extract certificate chain details from the SSL connection.
pub fn extract_chain_from_ssl(ssl: &SslRef) -> Vec<CertDetails> {
    collect_peer_chain(ssl)
        .iter()
        .map(|cert| x509_to_cert_details(cert.as_ref()))
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509, X509NameBuilder};

    fn make_test_cert(common_name: &str, issuer_common_name: &str) -> X509 {
        let rsa = Rsa::generate(2048).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();

        let mut subject_name = X509NameBuilder::new().unwrap();
        subject_name
            .append_entry_by_nid(Nid::COMMONNAME, common_name)
            .unwrap();
        let subject_name = subject_name.build();

        let mut issuer_name = X509NameBuilder::new().unwrap();
        issuer_name
            .append_entry_by_nid(Nid::COMMONNAME, issuer_common_name)
            .unwrap();
        let issuer_name = issuer_name.build();

        let mut serial = BigNum::new().unwrap();
        serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
        let serial = serial.to_asn1_integer().unwrap();

        let mut builder = openssl::x509::X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&serial).unwrap();
        builder.set_subject_name(&subject_name).unwrap();
        builder.set_issuer_name(&issuer_name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
            .unwrap();
        builder
            .set_not_after(Asn1Time::days_from_now(30).unwrap().as_ref())
            .unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    #[test]
    fn build_peer_chain_keeps_leaf_once_when_peer_chain_includes_it() {
        let leaf = make_test_cert("leaf.example.com", "Test Intermediate");
        let intermediate = make_test_cert("Test Intermediate", "Test Root");

        let chain = build_peer_chain(Some(leaf.as_ref()), [leaf.as_ref(), intermediate.as_ref()]);

        let common_names: Vec<_> = chain
            .iter()
            .map(|cert| x509_to_cert_details(cert.as_ref()).common_name)
            .collect();

        assert_eq!(common_names, vec!["leaf.example.com", "Test Intermediate"]);
    }

    #[test]
    fn build_peer_chain_deduplicates_repeated_intermediates() {
        let leaf = make_test_cert("leaf.example.com", "Test Intermediate");
        let intermediate = make_test_cert("Test Intermediate", "Test Root");

        let chain = build_peer_chain(
            Some(leaf.as_ref()),
            [leaf.as_ref(), intermediate.as_ref(), intermediate.as_ref()],
        );

        let common_names: Vec<_> = chain
            .iter()
            .map(|cert| x509_to_cert_details(cert.as_ref()).common_name)
            .collect();

        assert_eq!(common_names, vec!["leaf.example.com", "Test Intermediate"]);
    }

    #[test]
    fn build_peer_chain_returns_leaf_when_no_peer_stack_is_present() {
        let leaf = make_test_cert("leaf.example.com", "Test Intermediate");

        let chain = build_peer_chain(Some(leaf.as_ref()), std::iter::empty());

        let common_names: Vec<_> = chain
            .iter()
            .map(|cert| x509_to_cert_details(cert.as_ref()).common_name)
            .collect();

        assert_eq!(common_names, vec!["leaf.example.com"]);
    }

    #[test]
    fn x509_to_cert_details_extracts_extended_metadata() {
        let cert = make_test_cert("leaf.example.com", "Test Intermediate");

        let details = x509_to_cert_details(cert.as_ref());

        assert_eq!(details.common_name, "leaf.example.com");
        assert_eq!(details.issuer, "Test Intermediate");
        assert_eq!(details.public_key_bits, 2048);
        assert_eq!(details.signature_algorithm, "sha256WithRSAEncryption");
        assert!(!details.serial_number.is_empty());
        assert_ne!(details.serial_number, "Unknown");
        assert!(details.sha1_fingerprint.contains(':'));
        assert!(details.sha256_fingerprint.contains(':'));
    }
}

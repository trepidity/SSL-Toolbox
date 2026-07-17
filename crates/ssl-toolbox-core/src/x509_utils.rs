use anyhow::{Context, Result};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::ssl::SslRef;
use openssl::x509::X509VerifyResult;
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

pub fn x509_to_pem_string(cert: &X509Ref) -> Result<String> {
    let pem = cert
        .to_pem()
        .context("Failed to encode certificate as PEM")?;
    String::from_utf8(pem).context("PEM certificate contained invalid UTF-8")
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

/// True when `issuer_candidate`'s subject DN matches `subject`'s issuer DN.
fn subject_matches_issuer(issuer_candidate: &X509Ref, subject: &X509Ref) -> bool {
    match (
        issuer_candidate.subject_name().to_der(),
        subject.issuer_name().to_der(),
    ) {
        (Ok(subject_der), Ok(issuer_der)) => subject_der == issuer_der,
        _ => false,
    }
}

/// True when `subject`'s signature verifies against `issuer_candidate`'s public key —
/// the only cryptographic issuer test in this module.
fn signed_by(subject: &X509Ref, issuer_candidate: &X509Ref) -> bool {
    issuer_candidate
        .public_key()
        .and_then(|key| subject.verify(&key))
        .unwrap_or(false)
}

/// True when `issuer_candidate` claims to be the issuer of `subject`.
///
/// `issued()` wraps OpenSSL's `X509_check_issued`, which compares names and, when
/// present, AKID/SKID and keyUsage — it does NOT verify the signature; nor does the
/// DN fallback. Name-level matching is intentional here: this predicate feeds leaf
/// inference, where "claims to issue" is the question being asked.
fn is_issuer_of(issuer_candidate: &X509Ref, subject: &X509Ref) -> bool {
    issuer_candidate.issued(subject) == X509VerifyResult::OK
        || subject_matches_issuer(issuer_candidate, subject)
}

fn cert_der(cert: &X509Ref) -> Option<Vec<u8>> {
    cert.to_der().ok()
}

/// Find the index of the cert that issued `current` among `candidates`, in three tiers:
/// 1. subject/issuer DN match plus actual signature verification (cryptographic);
/// 2. `X509_check_issued` — name and AKID/SKID/keyUsage consistency, no signature check;
/// 3. subject/issuer DN equality alone (display-ordering fallback for broken bundles).
fn find_issuer_index(current: &X509Ref, candidates: &[X509]) -> Option<usize> {
    if let Some(idx) = candidates.iter().position(|candidate| {
        subject_matches_issuer(candidate.as_ref(), current)
            && signed_by(current, candidate.as_ref())
    }) {
        return Some(idx);
    }

    if let Some(idx) = candidates
        .iter()
        .position(|candidate| candidate.issued(current) == X509VerifyResult::OK)
    {
        return Some(idx);
    }

    candidates
        .iter()
        .position(|candidate| subject_matches_issuer(candidate.as_ref(), current))
}

/// Whether `cert` issues any other certificate in `all` (by signature or DN).
fn issues_any_other(cert: &X509Ref, all: &[X509]) -> bool {
    let self_der = cert_der(cert);
    all.iter().any(|other| {
        let other_der = cert_der(other.as_ref());
        if self_der.is_some() && self_der == other_der {
            return false;
        }
        is_issuer_of(cert, other.as_ref())
    })
}

/// Pick a leaf when the peer certificate API did not supply one.
/// Prefer an end-entity that does not issue any other cert in the set.
fn infer_leaf_index(certs: &[X509]) -> usize {
    if certs.len() <= 1 {
        return 0;
    }

    if let Some(idx) = certs
        .iter()
        .position(|cert| !issues_any_other(cert.as_ref(), certs))
    {
        return idx;
    }

    0
}

/// Rebuild a leaf-first path: leaf → intermediate(s) → root, using subject/issuer links.
/// Unlinked leftovers (if any) are appended after the reconstructed path.
fn order_certs_leaf_first(known_leaf: Option<&X509Ref>, mut certs: Vec<X509>) -> Vec<X509> {
    if certs.len() <= 1 {
        return certs;
    }

    let leaf_idx = if let Some(leaf) = known_leaf {
        let leaf_der = cert_der(leaf);
        certs
            .iter()
            .position(|cert| cert_der(cert.as_ref()) == leaf_der)
            .unwrap_or_else(|| infer_leaf_index(&certs))
    } else {
        infer_leaf_index(&certs)
    };

    let mut ordered = Vec::with_capacity(certs.len());
    ordered.push(certs.remove(leaf_idx));

    while !certs.is_empty() {
        let current = ordered.last().expect("ordered always has the leaf");
        match find_issuer_index(current.as_ref(), &certs) {
            Some(idx) => ordered.push(certs.remove(idx)),
            None => {
                // Cannot extend the path further; keep any remaining certs after it.
                ordered.extend(certs);
                break;
            }
        }
    }

    ordered
}

/// Peer chain reconstructed into leaf-first path order, plus whether the server's
/// presented (deduplicated) order differed from the reconstructed path.
pub struct PeerChainReport {
    pub chain: Vec<X509>,
    pub sent_out_of_order: bool,
}

fn build_peer_chain_report<'a, I>(leaf: Option<&'a X509Ref>, peer_chain: I) -> PeerChainReport
where
    I: IntoIterator<Item = &'a X509Ref>,
{
    let mut unique = Vec::new();
    let mut seen = HashSet::new();

    if let Some(leaf) = leaf {
        push_unique_cert(leaf, &mut unique, &mut seen);
    }

    for cert in peer_chain {
        push_unique_cert(cert, &mut unique, &mut seen);
    }

    let wire_ders: Vec<_> = unique.iter().map(|cert| cert_der(cert.as_ref())).collect();
    let chain = order_certs_leaf_first(leaf, unique);
    let sent_out_of_order = chain
        .iter()
        .map(|cert| cert_der(cert.as_ref()))
        .ne(wire_ders);

    PeerChainReport {
        chain,
        sent_out_of_order,
    }
}

fn filter_untrusted_intermediates(chain: Vec<X509>) -> Vec<X509> {
    chain
        .into_iter()
        .enumerate()
        .filter_map(|(idx, cert)| {
            if idx == 0 || cert.issued(cert.as_ref()) == X509VerifyResult::OK {
                None
            } else {
                Some(cert)
            }
        })
        .collect()
}

/// Collect the peer chain in leaf-first path order with duplicate certificates removed,
/// reporting whether the server's presented order differed from the reconstructed path.
///
/// Order is reconstructed from issuer relationships, tiered strongest-first: signature
/// verification, then OpenSSL's `X509_check_issued` (names and key identifiers — no
/// signature check), then subject/issuer DN equality — not from the order certificates
/// appeared in the TLS Certificate message.
pub fn collect_peer_chain_report(ssl: &SslRef) -> PeerChainReport {
    let leaf = ssl.peer_certificate();

    match ssl.peer_cert_chain() {
        Some(cert_stack) => {
            build_peer_chain_report(leaf.as_ref().map(|cert| cert.as_ref()), cert_stack.iter())
        }
        None => {
            build_peer_chain_report(leaf.as_ref().map(|cert| cert.as_ref()), std::iter::empty())
        }
    }
}

/// Collect the peer chain in leaf-first path order with duplicate certificates removed.
/// See [`collect_peer_chain_report`] for ordering semantics and the out-of-order flag.
pub fn collect_peer_chain(ssl: &SslRef) -> Vec<X509> {
    collect_peer_chain_report(ssl).chain
}

/// Collect the peer certificates that should be treated as untrusted intermediates for
/// verification. This excludes the leaf and any self-signed root sent by the server.
pub fn collect_peer_untrusted_chain(ssl: &SslRef) -> Vec<X509> {
    filter_untrusted_intermediates(collect_peer_chain(ssl))
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

    let cert_details_list = all_certs
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

    /// Chain-only convenience over `build_peer_chain_report` for tests that don't
    /// assert on the out-of-order flag.
    fn build_peer_chain<'a, I>(leaf: Option<&'a X509Ref>, peer_chain: I) -> Vec<X509>
    where
        I: IntoIterator<Item = &'a X509Ref>,
    {
        build_peer_chain_report(leaf, peer_chain).chain
    }

    fn make_test_cert(common_name: &str, issuer_common_name: &str) -> X509 {
        make_test_cert_with_key_usage(common_name, issuer_common_name, None)
    }

    /// `key_usage`: a keyUsage extension without `keyCertSign` makes `X509_check_issued`
    /// reject the cert as an issuer, forcing callers through the DN-equality fallback.
    fn make_test_cert_with_key_usage(
        common_name: &str,
        issuer_common_name: &str,
        key_usage: Option<openssl::x509::X509Extension>,
    ) -> X509 {
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
        if let Some(ext) = key_usage {
            builder.append_extension(ext).unwrap();
        }
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

    #[test]
    fn peer_untrusted_chain_excludes_self_signed_root() {
        let leaf = make_test_cert("leaf.example.com", "Test Intermediate");
        let intermediate = make_test_cert("Test Intermediate", "Test Root");
        let root = make_test_cert("Test Root", "Test Root");

        let chain = build_peer_chain(
            Some(leaf.as_ref()),
            [leaf.as_ref(), intermediate.as_ref(), root.as_ref()],
        );
        let untrusted = filter_untrusted_intermediates(chain);

        let common_names: Vec<_> = untrusted
            .iter()
            .map(|cert| x509_to_cert_details(cert.as_ref()).common_name)
            .collect();

        assert_eq!(common_names, vec!["Test Intermediate"]);
    }

    #[test]
    fn extract_cert_chain_details_preserves_pem_file_order() {
        let root = make_test_cert("Test Root", "Test Root");
        let intermediate = make_test_cert("Test Intermediate", "Test Root");
        let leaf = make_test_cert("leaf.example.com", "Test Intermediate");

        let mut bundle = Vec::new();
        bundle.extend(root.to_pem().unwrap());
        bundle.extend(intermediate.to_pem().unwrap());
        bundle.extend(leaf.to_pem().unwrap());

        let common_names: Vec<_> = extract_cert_chain_details(&bundle)
            .unwrap()
            .into_iter()
            .map(|cert| cert.common_name)
            .collect();

        assert_eq!(
            common_names,
            vec![
                "Test Root".to_string(),
                "Test Intermediate".to_string(),
                "leaf.example.com".to_string()
            ]
        );
    }

    /// Build a real signed hierarchy so `X509::issued()` relationships hold.
    ///
    /// `make_test_cert` only sets issuer *names* and self-signs each cert, so it cannot
    /// exercise path-building by signature. These certs form leaf ← intermediate ← root.
    fn make_signed_chain() -> (X509, X509, X509) {
        fn build_cert(
            subject_cn: &str,
            issuer_cn: &str,
            subject_key: &openssl::pkey::PKey<openssl::pkey::Private>,
            issuer_key: &openssl::pkey::PKey<openssl::pkey::Private>,
            is_ca: bool,
        ) -> X509 {
            let mut subject_name = X509NameBuilder::new().unwrap();
            subject_name
                .append_entry_by_nid(Nid::COMMONNAME, subject_cn)
                .unwrap();
            let subject_name = subject_name.build();

            let mut issuer_name = X509NameBuilder::new().unwrap();
            issuer_name
                .append_entry_by_nid(Nid::COMMONNAME, issuer_cn)
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
            builder.set_pubkey(subject_key).unwrap();
            builder
                .set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
                .unwrap();
            builder
                .set_not_after(Asn1Time::days_from_now(30).unwrap().as_ref())
                .unwrap();
            if is_ca {
                builder
                    .append_extension(
                        openssl::x509::extension::BasicConstraints::new()
                            .critical()
                            .ca()
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
            }
            builder.sign(issuer_key, MessageDigest::sha256()).unwrap();
            builder.build()
        }

        let root_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let int_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let leaf_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();

        let root = build_cert("Test Root", "Test Root", &root_key, &root_key, true);
        let intermediate = build_cert("Test Intermediate", "Test Root", &int_key, &root_key, true);
        let leaf = build_cert(
            "leaf.example.com",
            "Test Intermediate",
            &leaf_key,
            &int_key,
            false,
        );
        (leaf, intermediate, root)
    }

    #[test]
    fn build_peer_chain_orders_scrambled_intermediates_leaf_first_path() {
        let (leaf, intermediate, root) = make_signed_chain();

        // Peer stack: leaf, root, intermediate (invalid path order after the leaf).
        let chain = build_peer_chain(
            Some(leaf.as_ref()),
            [leaf.as_ref(), root.as_ref(), intermediate.as_ref()],
        );

        let common_names: Vec<_> = chain
            .iter()
            .map(|cert| x509_to_cert_details(cert.as_ref()).common_name)
            .collect();

        assert_eq!(
            common_names,
            vec![
                "leaf.example.com".to_string(),
                "Test Intermediate".to_string(),
                "Test Root".to_string()
            ],
            "scrambled peer stack was not rebuilt into a leaf-first issuer path; got {common_names:?}"
        );
    }

    #[test]
    fn build_peer_chain_orders_root_first_peer_stack_into_leaf_first_path() {
        let (leaf, intermediate, root) = make_signed_chain();

        let chain = build_peer_chain(
            Some(leaf.as_ref()),
            [root.as_ref(), intermediate.as_ref(), leaf.as_ref()],
        );

        let common_names: Vec<_> = chain
            .iter()
            .map(|cert| x509_to_cert_details(cert.as_ref()).common_name)
            .collect();

        assert_eq!(
            common_names,
            vec![
                "leaf.example.com".to_string(),
                "Test Intermediate".to_string(),
                "Test Root".to_string()
            ],
            "root-first peer stack was not rebuilt into leaf-first path; got {common_names:?}"
        );
    }

    /// Name-only certs (issuer DN set, but not actually signed by issuer) still order by
    /// subject/issuer DN match — the common real-world presentation case.
    ///
    /// The intermediate carries keyUsage WITHOUT keyCertSign so `X509_check_issued`
    /// rejects it as an issuer: only the subject/issuer DN fallback can link the leaf,
    /// guaranteeing this test actually exercises that branch.
    #[test]
    fn build_peer_chain_orders_by_subject_issuer_dn_without_signature_link() {
        let leaf = make_test_cert("leaf.example.com", "Test Intermediate");
        let intermediate = make_test_cert_with_key_usage(
            "Test Intermediate",
            "Test Root",
            Some(
                openssl::x509::extension::KeyUsage::new()
                    .digital_signature()
                    .build()
                    .unwrap(),
            ),
        );
        let root = make_test_cert("Test Root", "Test Root");

        let chain = build_peer_chain(
            Some(leaf.as_ref()),
            [root.as_ref(), intermediate.as_ref(), leaf.as_ref()],
        );

        let common_names: Vec<_> = chain
            .iter()
            .map(|cert| x509_to_cert_details(cert.as_ref()).common_name)
            .collect();

        assert_eq!(
            common_names,
            vec![
                "leaf.example.com".to_string(),
                "Test Intermediate".to_string(),
                "Test Root".to_string()
            ]
        );
    }

    /// A cert with the right subject DN but the wrong key (stale/rolled-over CA left in
    /// the bundle) must lose to the candidate whose key actually verifies the signature,
    /// regardless of wire position.
    #[test]
    fn build_peer_chain_prefers_signature_verified_issuer_over_same_name_impostor() {
        let (leaf, intermediate, root) = make_signed_chain();
        // Same subject DN as the real intermediate, different unrelated key, no AKID/SKID.
        let impostor = make_test_cert("Test Intermediate", "Test Root");

        let chain = build_peer_chain(
            Some(leaf.as_ref()),
            [
                leaf.as_ref(),
                impostor.as_ref(),
                intermediate.as_ref(),
                root.as_ref(),
            ],
        );

        let real_intermediate_fp = x509_to_cert_details(intermediate.as_ref()).sha256_fingerprint;
        let fingerprints: Vec<_> = chain
            .iter()
            .map(|cert| x509_to_cert_details(cert.as_ref()).sha256_fingerprint)
            .collect();

        assert_eq!(chain.len(), 4);
        assert_eq!(
            fingerprints[1], real_intermediate_fp,
            "wire-first same-DN impostor was chosen over the signature-verified issuer"
        );
    }

    #[test]
    fn build_peer_chain_report_flags_out_of_order_wire_stack() {
        let (leaf, intermediate, root) = make_signed_chain();

        let report = build_peer_chain_report(
            Some(leaf.as_ref()),
            [leaf.as_ref(), root.as_ref(), intermediate.as_ref()],
        );

        assert!(
            report.sent_out_of_order,
            "scrambled wire order must set sent_out_of_order"
        );
    }

    #[test]
    fn build_peer_chain_report_clear_for_path_ordered_wire_stack() {
        let (leaf, intermediate, root) = make_signed_chain();

        let report = build_peer_chain_report(
            Some(leaf.as_ref()),
            [leaf.as_ref(), intermediate.as_ref(), root.as_ref()],
        );
        assert!(!report.sent_out_of_order);

        // Deduplicating a repeated cert is not a reordering.
        let report = build_peer_chain_report(
            Some(leaf.as_ref()),
            [
                leaf.as_ref(),
                leaf.as_ref(),
                intermediate.as_ref(),
                root.as_ref(),
            ],
        );
        assert!(
            !report.sent_out_of_order,
            "dedup of a repeated leaf must not count as reordering"
        );
    }

    #[test]
    fn build_peer_chain_infers_leaf_when_peer_certificate_missing() {
        let (leaf, intermediate, root) = make_signed_chain();

        let chain = build_peer_chain(None, [root.as_ref(), intermediate.as_ref(), leaf.as_ref()]);

        let common_names: Vec<_> = chain
            .iter()
            .map(|cert| x509_to_cert_details(cert.as_ref()).common_name)
            .collect();

        assert_eq!(
            common_names,
            vec![
                "leaf.example.com".to_string(),
                "Test Intermediate".to_string(),
                "Test Root".to_string()
            ]
        );
    }
}

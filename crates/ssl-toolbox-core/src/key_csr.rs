use anyhow::{Context, Result};
use openssl::asn1::Asn1Object;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::symm::Cipher;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509, X509NameBuilder, X509Req, X509ReqBuilder};
use std::fs;
use std::net::IpAddr;

/// Generate a private key and CSR from an OpenSSL config file.
pub fn generate_key_and_csr(
    conf_file: &str,
    key_file: &str,
    csr_file: &str,
    password: &str,
) -> Result<()> {
    let rsa = Rsa::generate(2048).context("Failed to generate RSA key")?;
    let pkey = PKey::from_rsa(rsa).context("Failed to create PKey from RSA")?;

    let cipher = Cipher::aes_256_cbc();
    let encrypted_key = pkey
        .private_key_to_pem_pkcs8_passphrase(cipher, password.as_bytes())
        .context("Failed to encrypt private key")?;
    fs::write(key_file, encrypted_key).context("Failed to write key file")?;

    let mut builder = X509ReqBuilder::new().context("Failed to create X509ReqBuilder")?;
    builder
        .set_pubkey(&pkey)
        .context("Failed to set pubkey in CSR")?;

    let conf_content = fs::read_to_string(conf_file).context("Failed to read openssl.conf")?;

    let mut subject_fields = Vec::new();
    let mut san_fields = Vec::new();
    let mut current_section = String::new();

    for line in conf_content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].trim().to_string();
            continue;
        }

        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            if current_section == "req_distinguished_name" {
                subject_fields.push((k.to_string(), v.to_string()));
            } else if current_section == "alt_names" {
                san_fields.push((k.to_string(), v.to_string()));
            }
        }
    }

    let mut name_builder = X509NameBuilder::new()?;
    for (name, value) in subject_fields {
        let nid = match name.as_str() {
            "C" | "countryName" => Nid::COUNTRYNAME,
            "ST" | "stateOrProvinceName" => Nid::STATEORPROVINCENAME,
            "L" | "localityName" => Nid::LOCALITYNAME,
            "O" | "organizationName" => Nid::ORGANIZATIONNAME,
            "OU" | "organizationalUnitName" => Nid::ORGANIZATIONALUNITNAME,
            "CN" | "commonName" => Nid::COMMONNAME,
            "emailAddress" => Nid::PKCS9_EMAILADDRESS,
            other => Asn1Object::from_str(other)
                .map(|obj| obj.nid())
                .unwrap_or(Nid::UNDEF),
        };
        if nid != Nid::UNDEF {
            name_builder.append_entry_by_nid(nid, &value)?;
        }
    }
    builder
        .set_subject_name(&name_builder.build())
        .context("Failed to set subject name")?;

    if !san_fields.is_empty() {
        let mut san_builder = SubjectAlternativeName::new();

        for (name, value) in san_fields {
            if name.starts_with("DNS") {
                san_builder.dns(&value);
            } else if name.starts_with("IP") {
                san_builder.ip(&value);
            } else if name.starts_with("email") {
                san_builder.email(&value);
            } else if name.starts_with("URI") {
                san_builder.uri(&value);
            }
        }

        let ctx = builder.x509v3_context(None);
        let extension = san_builder
            .build(&ctx)
            .context("Failed to create SAN extension")?;
        let mut stack = Stack::new()?;
        stack.push(extension)?;
        builder
            .add_extensions(&stack)
            .context("Failed to add SAN extension to CSR")?;
    }

    builder
        .sign(&pkey, openssl::hash::MessageDigest::sha256())
        .context("Failed to sign CSR")?;

    let csr_pem = builder
        .build()
        .to_pem()
        .context("Failed to generate CSR PEM")?;
    fs::write(csr_file, csr_pem).context("Failed to write CSR file")?;

    Ok(())
}

/// Extract CN and SANs from a CSR file (PEM or DER).
pub fn extract_csr_details(csr_file: &str) -> Result<(String, Vec<String>)> {
    let input_bytes = fs::read(csr_file).context("Failed to read CSR file")?;

    let req = X509Req::from_pem(&input_bytes)
        .or_else(|_| X509Req::from_der(&input_bytes))
        .context("Failed to parse CSR")?;

    let subject = req.subject_name();

    let cn = subject
        .entries()
        .find(|entry| entry.object().nid() == Nid::COMMONNAME)
        .and_then(|entry| entry.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "N/A".to_string());

    let mut san_list = Vec::new();

    // Use a temporary certificate to extract SANs via high-level API
    let mut temp_builder = X509::builder()?;
    temp_builder.set_subject_name(req.subject_name())?;
    let pkey = req.public_key()?;
    temp_builder.set_pubkey(&pkey)?;
    if let Ok(extensions) = req.extensions() {
        for ext in extensions {
            let _ = temp_builder.append_extension(ext);
        }
    }
    let temp_cert = temp_builder.build();
    if let Some(sans) = temp_cert.subject_alt_names() {
        for n in sans {
            if let Some(dns) = n.dnsname() {
                san_list.push(format!("DNS: {}", dns));
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
                san_list.push(format!("IP: {}", addr));
            } else if let Some(email) = n.email() {
                san_list.push(format!("Email: {}", email));
            } else if let Some(uri) = n.uri() {
                san_list.push(format!("URI: {}", uri));
            }
        }
    }

    Ok((cn, san_list))
}

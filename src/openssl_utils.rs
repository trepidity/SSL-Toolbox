use anyhow::{Result, Context};
use openssl::pkey::{PKey};
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509Req, X509NameBuilder, X509ReqBuilder, X509Name, GeneralName};
use openssl::x509::extension::SubjectAlternativeName;
use openssl::pkcs12::Pkcs12;
use openssl::symm::Cipher;
use openssl::nid::Nid;
use openssl::stack::Stack;
use openssl::asn1::Asn1Object;
use std::fs;
use std::net::IpAddr;

pub fn generate_key_and_csr(conf_file: &str, key_file: &str, csr_file: &str, password: &str) -> Result<()> {
    let rsa = Rsa::generate(2048).context("Failed to generate RSA key")?;
    let pkey = PKey::from_rsa(rsa).context("Failed to create PKey from RSA")?;

    let cipher = Cipher::aes_256_cbc();
    let encrypted_key = pkey.private_key_to_pem_pkcs8_passphrase(cipher, password.as_bytes())
        .context("Failed to encrypt private key")?;
    fs::write(key_file, encrypted_key).context("Failed to write key file")?;

    let mut builder = X509ReqBuilder::new().context("Failed to create X509ReqBuilder")?;
    builder.set_pubkey(&pkey).context("Failed to set pubkey in CSR")?;

    let conf_content = fs::read_to_string(conf_file).context("Failed to read openssl.conf")?;
    
    let mut subject_fields = Vec::new();
    let mut san_fields = Vec::new();
    let mut current_section = String::new();

    for line in conf_content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        
        // Handle section headers with optional spaces: [ section_name ]
        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len()-1].trim().to_string();
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
            other => {
                // Robust NID resolution using Asn1Object
                Asn1Object::from_str(other)
                    .map(|obj| obj.nid())
                    .unwrap_or(Nid::UNDEF)
            }
        };
        if nid != Nid::UNDEF {
            name_builder.append_entry_by_nid(nid, &value)?;
        }
    }
    builder.set_subject_name(&name_builder.build()).context("Failed to set subject name")?;

    if !san_fields.is_empty() {
        let mut san_builder = SubjectAlternativeName::new();
        
        for (name, value) in san_fields {
            // Support formats like DNS.1 = ..., DNS = ..., etc.
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
        let extension = san_builder.build(&ctx)
            .context("Failed to create SAN extension")?;
        let mut stack = Stack::new()?;
        stack.push(extension)?;
        builder.add_extensions(&stack).context("Failed to add SAN extension to CSR")?;
    }

    builder.sign(&pkey, openssl::hash::MessageDigest::sha256())
        .context("Failed to sign CSR")?;

    let csr_pem = builder.build().to_pem().context("Failed to generate CSR PEM")?;
    fs::write(csr_file, csr_pem).context("Failed to write CSR file")?;

    Ok(())
}

pub fn create_pfx(
    key_file: &str, 
    cert_file: &str, 
    chain_file: Option<&str>, 
    pfx_file: &str, 
    key_password: Option<&str>,
    pfx_password: &str
) -> Result<()> {
    let key_pem = fs::read(key_file).context("Failed to read key file")?;
    let cert_pem = fs::read(cert_file).context("Failed to read cert file")?;
    
    // Try to load the private key - first without password, then with password if provided
    let pkey = match PKey::private_key_from_pem(&key_pem) {
        Ok(key) => key,
        Err(_) => {
            // Key is encrypted, need a password
            if let Some(pass) = key_password {
                PKey::private_key_from_pem_passphrase(&key_pem, pass.as_bytes())
                    .context("Failed to parse private key (incorrect password)")?
            } else {
                return Err(anyhow::anyhow!("Private key is encrypted but no password was provided"));
            }
        }
    };
    
    // Load all certificates from the cert file
    let all_certs = X509::stack_from_pem(&cert_pem)
        .context("Failed to parse certificate file")?;
    
    if all_certs.is_empty() {
        return Err(anyhow::anyhow!("No certificates found in cert file"));
    }
    
    // The end-entity certificate is typically the last one in the chain
    // (or the first one if it's just a single cert)
    let cert = if all_certs.len() == 1 {
        all_certs[0].clone()
    } else {
        // When multiple certs are present, the last one is usually the end-entity cert
        all_certs[all_certs.len() - 1].clone()
    };
    
    let mut builder = Pkcs12::builder();
    
    // If the cert file contains a chain (more than one cert), use the rest as the chain
    if all_certs.len() > 1 {
        let mut chain_stack = Stack::new()?;
        // Add all certificates except the last one (end-entity) to the chain
        for i in 0..(all_certs.len() - 1) {
            chain_stack.push(all_certs[i].clone())?;
        }
        builder.ca(chain_stack);
    } else if let Some(chain_path) = chain_file {
        // If a separate chain file was provided, use it
        let chain_pem = fs::read(chain_path).context("Failed to read chain file")?;
        let chain_vec = X509::stack_from_pem(&chain_pem).context("Failed to parse chain certificates")?;
        let mut chain_stack = Stack::new()?;
        for c in chain_vec {
            chain_stack.push(c)?;
        }
        builder.ca(chain_stack);
    }

    let pfx = builder.pkey(&pkey).cert(&cert).name("Certificate").build2(pfx_password)
        .context("Failed to build PKCS12/PFX")?;
    
    let pfx_der = pfx.to_der().context("Failed to generate PFX DER")?;
    fs::write(pfx_file, pfx_der).context("Failed to write PFX file")?;

    Ok(())
}

fn extract_sans_into(sans: Stack<GeneralName>, san_list: &mut Vec<(String, String)>) {
    for n in sans {
        if let Some(dns) = n.dnsname() {
            san_list.push(("DNS".to_string(), dns.to_string()));
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
            san_list.push(("IP".to_string(), addr.to_string()));
        } else if let Some(email) = n.email() {
            san_list.push(("email".to_string(), email.to_string()));
        } else if let Some(uri) = n.uri() {
            san_list.push(("URI".to_string(), uri.to_string()));
        }
    }
}

pub fn generate_conf_from_cert_or_csr(input_file: &str, output_conf: &str, is_csr: bool) -> Result<()> {
    let mut config = String::new();
    config.push_str("[ req ]\n\n");
    config.push_str("[ req_distinguished_name ]\n");

    let input_bytes = fs::read(input_file).context("Failed to read input file")?;

    let mut san_list = Vec::new();
    let subject: X509Name;

    if is_csr {
        let req = X509Req::from_pem(&input_bytes)
            .or_else(|_| X509Req::from_der(&input_bytes))
            .context("Failed to parse CSR")?;
        subject = req.subject_name().to_owned()?;

        // Use a "temporary certificate" trick to extract SANs using high-level API
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
            extract_sans_into(sans, &mut san_list);
        }
    } else {
        let cert = X509::from_pem(&input_bytes)
            .or_else(|_| X509::from_der(&input_bytes))
            .context("Failed to parse certificate")?;
        subject = cert.subject_name().to_owned()?;

        if let Some(sans) = cert.subject_alt_names() {
            extract_sans_into(sans, &mut san_list);
        }
    };

    for entry in subject.entries() {
        if let Ok(sn) = entry.object().nid().short_name() {
            let value = entry.data().as_utf8()?.to_string();
            config.push_str(&format!("{} = {}\n", sn, value));
        }
    }

    if !san_list.is_empty() {
        config.push_str("\n[ v3_req ]\n");
        config.push_str("subjectAltName = @alt_names\n\n");
        config.push_str("[ alt_names ]\n");
        let mut counts = std::collections::HashMap::new();
        for (kind, val) in san_list {
            let count = counts.entry(kind.clone()).or_insert(0);
            *count += 1;
            config.push_str(&format!("{}.{} = {}\n", kind, count, val));
        }
    }

    fs::write(output_conf, config)?;
    Ok(())
}

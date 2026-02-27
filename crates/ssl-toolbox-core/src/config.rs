use anyhow::{Context, Result};
use openssl::stack::Stack;
use openssl::x509::{GeneralName, X509, X509Req};
use std::fs;
use std::net::IpAddr;

use crate::ConfigInputs;

/// Generate an OpenSSL configuration file from user inputs.
pub fn generate_conf_from_inputs(inputs: &ConfigInputs, output_path: &str) -> Result<()> {
    let mut config = String::new();

    config.push_str("[ req ]\n");
    config.push_str(&format!("default_bits        = {}\n", inputs.key_size));
    config.push_str("default_md          = sha256\n");
    config.push_str("string_mask         = utf8only\n");
    config.push_str("distinguished_name  = req_distinguished_name\n");
    config.push_str("req_extensions      = v3_req\n");
    config.push_str("prompt              = no\n");

    config.push_str("\n[ req_distinguished_name ]\n");
    config.push_str(&format!("countryName             = {}\n", inputs.country));
    config.push_str(&format!("stateOrProvinceName     = {}\n", inputs.state));
    config.push_str(&format!("localityName            = {}\n", inputs.locality));
    config.push_str(&format!(
        "organizationName        = {}\n",
        inputs.organization
    ));
    config.push_str(&format!("organizationalUnitName  = {}\n", inputs.org_unit));
    config.push_str(&format!(
        "commonName              = {}\n",
        inputs.common_name
    ));
    config.push_str(&format!("emailAddress            = {}\n", inputs.email));

    config.push_str("\n[ v3_req ]\n");
    config.push_str("basicConstraints        = CA:FALSE\n");
    config.push_str("keyUsage                = critical, digitalSignature, keyEncipherment\n");
    config.push_str(&format!(
        "extendedKeyUsage        = {}\n",
        inputs.extended_key_usage
    ));
    config.push_str("subjectKeyIdentifier    = hash\n");
    config.push_str("subjectAltName          = @alt_names\n");

    config.push_str("\n[ alt_names ]\n");
    let mut dns_idx = 1;
    config.push_str(&format!("DNS.{} = {}\n", dns_idx, inputs.common_name));
    dns_idx += 1;
    for dns in &inputs.san_dns {
        config.push_str(&format!("DNS.{} = {}\n", dns_idx, dns));
        dns_idx += 1;
    }
    for (i, ip) in inputs.san_ips.iter().enumerate() {
        config.push_str(&format!("IP.{} = {}\n", i + 1, ip));
    }

    fs::write(output_path, config).context("Failed to write config file")?;
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
                _ => return,
            };
            san_list.push(("IP".to_string(), addr.to_string()));
        } else if let Some(email) = n.email() {
            san_list.push(("email".to_string(), email.to_string()));
        } else if let Some(uri) = n.uri() {
            san_list.push(("URI".to_string(), uri.to_string()));
        }
    }
}

/// Generate an OpenSSL config file from an existing certificate or CSR.
pub fn generate_conf_from_cert_or_csr(
    input_file: &str,
    output_conf: &str,
    is_csr: bool,
) -> Result<()> {
    let mut config = String::new();
    config.push_str("[ req ]\n\n");
    config.push_str("[ req_distinguished_name ]\n");

    let input_bytes = fs::read(input_file).context("Failed to read input file")?;

    let mut san_list = Vec::new();
    let subject: openssl::x509::X509Name;

    if is_csr {
        let req = X509Req::from_pem(&input_bytes)
            .or_else(|_| X509Req::from_der(&input_bytes))
            .context("Failed to parse CSR")?;
        subject = req.subject_name().to_owned()?;

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

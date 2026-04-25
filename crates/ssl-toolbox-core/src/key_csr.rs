use anyhow::{Context, Result, anyhow};
use openssl::asn1::Asn1Object;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::symm::Cipher;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509, X509Name, X509NameBuilder, X509Req, X509ReqBuilder};
use std::fs;
use std::net::IpAddr;

#[derive(Debug, Clone)]
struct RequestConfig {
    subject_fields: Vec<(String, String)>,
    san_fields: Vec<(String, String)>,
}

/// Generate an encrypted private key.
pub fn generate_private_key(key_file: &str, password: &str) -> Result<()> {
    let rsa = Rsa::generate(2048).context("Failed to generate RSA key")?;
    let pkey = PKey::from_rsa(rsa).context("Failed to create PKey from RSA")?;

    let cipher = Cipher::aes_256_cbc();
    let encrypted_key = pkey
        .private_key_to_pem_pkcs8_passphrase(cipher, password.as_bytes())
        .context("Failed to encrypt private key")?;
    fs::write(key_file, encrypted_key).context("Failed to write key file")?;
    Ok(())
}

/// Generate a CSR from an OpenSSL config file and an existing private key.
pub fn generate_csr(
    conf_file: &str,
    key_file: &str,
    csr_file: &str,
    key_password: Option<&str>,
) -> Result<()> {
    let key_pem = fs::read(key_file).context("Failed to read key file")?;
    let pkey = load_private_key(&key_pem, key_password)?;

    let mut builder = X509ReqBuilder::new().context("Failed to create X509ReqBuilder")?;
    builder
        .set_pubkey(&pkey)
        .context("Failed to set pubkey in CSR")?;

    let request_config = load_request_config(conf_file)?;
    let subject_name = build_subject_name(&request_config.subject_fields)?;
    builder
        .set_subject_name(&subject_name)
        .context("Failed to set subject name")?;

    add_san_extension(&mut builder, &request_config.san_fields)?;

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

/// Generate a private key and CSR from an OpenSSL config file.
pub fn generate_key_and_csr(
    conf_file: &str,
    key_file: &str,
    csr_file: &str,
    password: &str,
) -> Result<()> {
    generate_private_key(key_file, password)?;
    generate_csr(conf_file, key_file, csr_file, Some(password))
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

fn load_private_key(
    key_pem: &[u8],
    key_password: Option<&str>,
) -> Result<PKey<openssl::pkey::Private>> {
    if let Ok(key) = PKey::private_key_from_pem(key_pem) {
        return Ok(key);
    }

    let password = key_password
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "Private key is encrypted or unreadable; a password is required to generate the CSR"
            )
        })?;

    PKey::private_key_from_pem_passphrase(key_pem, password.as_bytes())
        .context("Failed to decrypt private key")
}

fn load_request_config(conf_file: &str) -> Result<RequestConfig> {
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

    Ok(RequestConfig {
        subject_fields,
        san_fields,
    })
}

fn build_subject_name(subject_fields: &[(String, String)]) -> Result<X509Name> {
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
            name_builder.append_entry_by_nid(nid, value)?;
        }
    }

    Ok(name_builder.build())
}

fn add_san_extension(builder: &mut X509ReqBuilder, san_fields: &[(String, String)]) -> Result<()> {
    if san_fields.is_empty() {
        return Ok(());
    }

    let mut san_builder = SubjectAlternativeName::new();

    for (name, value) in san_fields {
        if name.starts_with("DNS") {
            san_builder.dns(value);
        } else if name.starts_with("IP") {
            san_builder.ip(value);
        } else if name.starts_with("email") {
            san_builder.email(value);
        } else if name.starts_with("URI") {
            san_builder.uri(value);
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ssl-toolbox-key-csr-{label}-{}-{nonce}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn write_config(path: &Path) {
        fs::write(
            path,
            r#"[req_distinguished_name]
C = US
ST = Texas
L = Austin
O = SSL Toolbox
OU = Platform
CN = svc.example.test
emailAddress = certs@example.test

[alt_names]
DNS.1 = svc.example.test
DNS.2 = api.example.test
"#,
        )
        .expect("write config");
    }

    #[test]
    fn generates_csr_from_existing_encrypted_key() {
        let dir = temp_dir("encrypted");
        let conf = dir.join("openssl.cnf");
        let key = dir.join("server.key");
        let csr = dir.join("server.csr");
        write_config(&conf);

        generate_private_key(key.to_str().unwrap(), "changeit").expect("generate key");
        generate_csr(
            conf.to_str().unwrap(),
            key.to_str().unwrap(),
            csr.to_str().unwrap(),
            Some("changeit"),
        )
        .expect("generate csr");

        let (cn, sans) = extract_csr_details(csr.to_str().unwrap()).expect("extract csr");
        assert_eq!(cn, "svc.example.test");
        assert_eq!(sans.len(), 2);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_encrypted_key_without_password() {
        let dir = temp_dir("missing-password");
        let conf = dir.join("openssl.cnf");
        let key = dir.join("server.key");
        let csr = dir.join("server.csr");
        write_config(&conf);

        generate_private_key(key.to_str().unwrap(), "changeit").expect("generate key");
        let error = generate_csr(
            conf.to_str().unwrap(),
            key.to_str().unwrap(),
            csr.to_str().unwrap(),
            None,
        )
        .expect_err("missing password should fail");

        assert!(error.to_string().contains("password is required"));

        let _ = fs::remove_dir_all(dir);
    }
}

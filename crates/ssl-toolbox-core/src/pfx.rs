use anyhow::{Context, Result};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509::X509;
use std::fs;

use crate::CertDetails;
use crate::x509_utils::x509_to_cert_details;

/// Create a PFX/PKCS12 file from a private key, certificate, and optional chain.
pub fn create_pfx(
    key_file: &str,
    cert_file: &str,
    chain_file: Option<&str>,
    pfx_file: &str,
    key_password: Option<&str>,
    pfx_password: &str,
) -> Result<()> {
    let key_pem = fs::read(key_file).context("Failed to read key file")?;
    let cert_pem = fs::read(cert_file).context("Failed to read cert file")?;

    let pkey = match PKey::private_key_from_pem(&key_pem) {
        Ok(key) => key,
        Err(_) => {
            if let Some(pass) = key_password {
                PKey::private_key_from_pem_passphrase(&key_pem, pass.as_bytes())
                    .context("Failed to parse private key (incorrect password)")?
            } else {
                return Err(anyhow::anyhow!(
                    "Private key is encrypted but no password was provided"
                ));
            }
        }
    };

    let all_certs = X509::stack_from_pem(&cert_pem).context("Failed to parse certificate file")?;

    if all_certs.is_empty() {
        return Err(anyhow::anyhow!("No certificates found in cert file"));
    }

    let cert = if all_certs.len() == 1 {
        all_certs[0].clone()
    } else {
        all_certs[all_certs.len() - 1].clone()
    };

    let mut builder = Pkcs12::builder();

    if all_certs.len() > 1 {
        let mut chain_stack = Stack::new()?;
        for cert in all_certs.iter().take(all_certs.len() - 1) {
            chain_stack.push(cert.clone())?;
        }
        builder.ca(chain_stack);
    } else if let Some(chain_path) = chain_file {
        let chain_pem = fs::read(chain_path).context("Failed to read chain file")?;
        let chain_vec =
            X509::stack_from_pem(&chain_pem).context("Failed to parse chain certificates")?;
        let mut chain_stack = Stack::new()?;
        for c in chain_vec {
            chain_stack.push(c)?;
        }
        builder.ca(chain_stack);
    }

    let pfx = builder
        .pkey(&pkey)
        .cert(&cert)
        .name("Certificate")
        .build2(pfx_password)
        .context("Failed to build PKCS12/PFX")?;

    let pfx_der = pfx.to_der().context("Failed to generate PFX DER")?;
    fs::write(pfx_file, pfx_der).context("Failed to write PFX file")?;

    Ok(())
}

/// Extract certificate details from a PFX/PKCS12 file.
pub fn extract_pfx_details(pfx_bytes: &[u8], password: &str) -> Result<Vec<CertDetails>> {
    let pkcs12 = Pkcs12::from_der(pfx_bytes).context("Failed to parse PFX/PKCS12 file")?;

    let parsed = pkcs12
        .parse2(password)
        .context("Failed to decrypt PFX (wrong password?)")?;

    let mut details = Vec::new();

    if let Some(cert) = &parsed.cert {
        details.push(x509_to_cert_details(cert));
    }

    if let Some(ca_stack) = &parsed.ca {
        for cert in ca_stack {
            details.push(x509_to_cert_details(cert));
        }
    }

    if details.is_empty() {
        return Err(anyhow::anyhow!("No certificates found in PFX file"));
    }

    Ok(details)
}

/// Convert an existing PFX to legacy TripleDES-SHA1 format for compatibility
/// with older systems (Windows Server 2012, Java 8, etc.).
pub fn create_pfx_legacy_3des(
    input_pfx: &[u8],
    input_password: &str,
    output_file: &str,
    output_password: &str,
) -> Result<()> {
    let pkcs12 = Pkcs12::from_der(input_pfx).context("Failed to parse input PFX")?;
    let parsed = pkcs12
        .parse2(input_password)
        .context("Failed to decrypt input PFX (wrong password?)")?;

    let pkey = parsed
        .pkey
        .ok_or_else(|| anyhow::anyhow!("No private key found in PFX"))?;
    let cert = parsed
        .cert
        .ok_or_else(|| anyhow::anyhow!("No certificate found in PFX"))?;

    let mut builder = Pkcs12::builder();
    builder.key_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC);
    builder.cert_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC);
    builder.mac_md(MessageDigest::sha1());

    if let Some(ca_stack) = parsed.ca {
        let mut chain_stack = Stack::new()?;
        for ca_cert in ca_stack {
            chain_stack.push(ca_cert)?;
        }
        builder.ca(chain_stack);
    }

    let pfx = builder
        .pkey(&pkey)
        .cert(&cert)
        .name("Certificate")
        .build2(output_password)
        .context("Failed to build legacy PFX")?;

    let pfx_der = pfx.to_der().context("Failed to generate legacy PFX DER")?;
    fs::write(output_file, pfx_der).context("Failed to write legacy PFX file")?;

    Ok(())
}

/// Create a PFX directly from key+cert using legacy TripleDES-SHA1 format.
pub fn create_pfx_legacy(
    key_file: &str,
    cert_file: &str,
    chain_file: Option<&str>,
    pfx_file: &str,
    key_password: Option<&str>,
    pfx_password: &str,
) -> Result<()> {
    let key_pem = fs::read(key_file).context("Failed to read key file")?;
    let cert_pem = fs::read(cert_file).context("Failed to read cert file")?;

    let pkey = match PKey::private_key_from_pem(&key_pem) {
        Ok(key) => key,
        Err(_) => {
            if let Some(pass) = key_password {
                PKey::private_key_from_pem_passphrase(&key_pem, pass.as_bytes())
                    .context("Failed to parse private key (incorrect password)")?
            } else {
                return Err(anyhow::anyhow!(
                    "Private key is encrypted but no password was provided"
                ));
            }
        }
    };

    let all_certs = X509::stack_from_pem(&cert_pem).context("Failed to parse certificate file")?;

    if all_certs.is_empty() {
        return Err(anyhow::anyhow!("No certificates found in cert file"));
    }

    let cert = if all_certs.len() == 1 {
        all_certs[0].clone()
    } else {
        all_certs[all_certs.len() - 1].clone()
    };

    let mut builder = Pkcs12::builder();
    builder.key_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC);
    builder.cert_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC);
    builder.mac_md(MessageDigest::sha1());

    if all_certs.len() > 1 {
        let mut chain_stack = Stack::new()?;
        for cert in all_certs.iter().take(all_certs.len() - 1) {
            chain_stack.push(cert.clone())?;
        }
        builder.ca(chain_stack);
    } else if let Some(chain_path) = chain_file {
        let chain_pem = fs::read(chain_path).context("Failed to read chain file")?;
        let chain_vec =
            X509::stack_from_pem(&chain_pem).context("Failed to parse chain certificates")?;
        let mut chain_stack = Stack::new()?;
        for c in chain_vec {
            chain_stack.push(c)?;
        }
        builder.ca(chain_stack);
    }

    let pfx = builder
        .pkey(&pkey)
        .cert(&cert)
        .name("Certificate")
        .build2(pfx_password)
        .context("Failed to build legacy PFX")?;

    let pfx_der = pfx.to_der().context("Failed to generate legacy PFX DER")?;
    fs::write(pfx_file, pfx_der).context("Failed to write legacy PFX file")?;

    Ok(())
}

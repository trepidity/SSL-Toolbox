use anyhow::{Context, Result};
use openssl::pkcs12::Pkcs12;
use openssl::x509::X509;
use std::fs;

use crate::CertFormat;

/// Auto-detect the format of certificate data by inspecting markers and trying parsers.
pub fn detect_format(data: &[u8]) -> CertFormat {
    if is_pkcs7_pem(data) {
        return CertFormat::Pkcs7;
    }

    // Check for PEM markers
    if let Ok(text) = std::str::from_utf8(data)
        && text.contains("-----BEGIN ")
    {
        return CertFormat::Pem;
    }

    if is_pkcs7_der(data) {
        return CertFormat::Pkcs7;
    }

    // Try PKCS12 (DER-encoded, starts with specific ASN.1 sequence)
    if Pkcs12::from_der(data).is_ok() {
        return CertFormat::Pkcs12;
    }

    // Try DER certificate
    if X509::from_der(data).is_ok() {
        return CertFormat::Der;
    }

    // Check if it looks like pure base64 (no PEM headers)
    if let Ok(text) = std::str::from_utf8(data) {
        let trimmed = text.trim();
        if !trimmed.is_empty()
            && !trimmed.contains("-----")
            && trimmed.chars().all(|c| {
                c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c.is_whitespace()
            })
        {
            // Verify it actually decodes
            let no_whitespace: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
            if base64_decode(&no_whitespace).is_some() {
                return CertFormat::Base64;
            }
        }
    }

    CertFormat::Unknown
}

fn is_pkcs7_pem(data: &[u8]) -> bool {
    if let Ok(text) = std::str::from_utf8(data) {
        text.contains("-----BEGIN PKCS7-----") || text.contains("-----BEGIN CMS-----")
    } else {
        false
    }
}

fn is_pkcs7_der(data: &[u8]) -> bool {
    // PKCS#7 signedData OID: 1.2.840.113549.1.7.2
    // DER-encoded: 06 09 2A 86 48 86 F7 0D 01 07 02
    let oid = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
    ];
    let window = data.get(..data.len().min(30)).unwrap_or(data);
    window.windows(oid.len()).any(|w| w == oid)
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    // Simple base64 decoder without external deps
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    let input: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();

    for chunk in input.chunks(4) {
        let mut buf = [0u8; 4];
        let len = chunk.len();
        for (i, &byte) in chunk.iter().enumerate() {
            buf[i] = match TABLE.iter().position(|&b| b == byte) {
                Some(pos) => pos as u8,
                None => return None,
            };
        }
        if len >= 2 {
            output.push((buf[0] << 2) | (buf[1] >> 4));
        }
        if len >= 3 {
            output.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if len >= 4 {
            output.push((buf[2] << 6) | buf[3]);
        }
    }

    Some(output)
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        result.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Convert PEM to DER format.
pub fn pem_to_der(input: &str, output: &str) -> Result<()> {
    let data = fs::read(input).context("Failed to read input file")?;
    let cert = X509::from_pem(&data).context("Failed to parse PEM certificate")?;
    let der = cert.to_der().context("Failed to convert to DER")?;
    fs::write(output, der).context("Failed to write DER file")?;
    Ok(())
}

/// Convert DER to PEM format.
pub fn der_to_pem(input: &str, output: &str) -> Result<()> {
    let data = fs::read(input).context("Failed to read input file")?;
    let cert = X509::from_der(&data).context("Failed to parse DER certificate")?;
    let pem = cert.to_pem().context("Failed to convert to PEM")?;
    fs::write(output, pem).context("Failed to write PEM file")?;
    Ok(())
}

/// Convert PEM to raw Base64 (strip PEM headers/footers).
pub fn pem_to_base64(input: &str, output: &str) -> Result<()> {
    let data = fs::read(input).context("Failed to read input file")?;
    let cert = X509::from_pem(&data).context("Failed to parse PEM certificate")?;
    let der = cert.to_der().context("Failed to convert to DER")?;
    let b64 = base64_encode(&der);

    // Write with line wrapping at 76 chars
    let mut wrapped = String::new();
    for (i, ch) in b64.chars().enumerate() {
        if i > 0 && i % 76 == 0 {
            wrapped.push('\n');
        }
        wrapped.push(ch);
    }
    wrapped.push('\n');

    fs::write(output, wrapped).context("Failed to write Base64 file")?;
    Ok(())
}

/// Return a human-readable description of the detected format.
pub fn format_description(format: CertFormat) -> &'static str {
    match format {
        CertFormat::Pem => "PEM (Base64-encoded with headers)",
        CertFormat::Der => "DER (binary ASN.1)",
        CertFormat::Pkcs12 => "PKCS#12 / PFX (binary container)",
        CertFormat::Pkcs7 => "PKCS#7 / P7B (certificate bundle)",
        CertFormat::Base64 => "Raw Base64 (no PEM headers)",
        CertFormat::Unknown => "Unknown format",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pkcs7_pem_before_generic_pem() {
        let data = b"-----BEGIN PKCS7-----\nMIIB\n-----END PKCS7-----\n";
        assert_eq!(detect_format(data), CertFormat::Pkcs7);
    }

    #[test]
    fn detects_pkcs7_cms_pem_before_generic_pem() {
        let data = b"-----BEGIN CMS-----\nMIIB\n-----END CMS-----\n";
        assert_eq!(detect_format(data), CertFormat::Pkcs7);
    }

    #[test]
    fn detects_regular_pem_certificate() {
        let data = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        assert_eq!(detect_format(data), CertFormat::Pem);
    }

    #[test]
    fn detects_pkcs7_der_before_pkcs12_and_der_cert() {
        let oid = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
        ];
        let mut data = vec![0x30, 0x82, 0x01, 0x00, 0xA0];
        data.extend_from_slice(&oid);
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        assert_eq!(detect_format(&data), CertFormat::Pkcs7);
    }

    #[test]
    fn format_description_includes_pkcs7() {
        assert_eq!(
            format_description(CertFormat::Pkcs7),
            "PKCS#7 / P7B (certificate bundle)"
        );
    }
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertDetails {
    pub common_name: String,
    pub sans: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub issuer: String,
    pub signature_algorithm: String,
    pub public_key_bits: u32,
    pub serial_number: String,
    pub sha1_fingerprint: String,
    pub sha256_fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct ConfigInputs {
    pub common_name: String,
    pub country: String,
    pub state: String,
    pub locality: String,
    pub organization: String,
    pub org_unit: String,
    pub email: String,
    pub san_dns: Vec<String>,
    pub san_ips: Vec<String>,
    pub key_size: u32,
    pub extended_key_usage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertValidation {
    pub hostname_match: Option<ValidationResult>,
    pub expiry_check: Option<ValidationResult>,
    pub chain_valid: Option<ValidationResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub passed: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherInfo {
    pub name: String,
    pub bits: i32,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsVersionProbeResult {
    pub label: String,
    pub supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCheckResult {
    pub host: String,
    pub port: u16,
    pub cipher: CipherInfo,
    pub cert_chain: Vec<CertDetails>,
    pub version_support: Vec<TlsVersionProbeResult>,
    pub validation: Option<CertValidation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertFormat {
    Pem,
    Der,
    Pkcs12,
    Pkcs7,
    Base64,
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CsrDefaults {
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub locality: String,
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub org_unit: String,
    #[serde(default)]
    pub email: String,
}

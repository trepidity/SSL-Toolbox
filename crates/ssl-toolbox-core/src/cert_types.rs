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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKeySummary {
    pub present: bool,
    pub algorithm: String,
    pub key_size_bits: u32,
    pub security_bits: u32,
    pub matches_leaf_certificate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfxDetails {
    pub cert_chain: Vec<CertDetails>,
    pub private_key: PrivateKeySummary,
}

/// A `GeneralName` choice from RFC 5280 §4.2.1.6, restricted to the seven that
/// OpenSSL's `subjectAltName` config syntax can express.
///
/// `x400Address` [3] and `ediPartyName` [5] are deliberately absent: RFC 5280
/// defines them, but `openssl.cnf` has no syntax for either, so a config file
/// cannot carry them at all. Offering them would produce a config OpenSSL
/// rejects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SanKind {
    /// `dNSName` [2]
    Dns,
    /// `iPAddress` [7]
    Ip,
    /// `rfc822Name` [1]
    Email,
    /// `uniformResourceIdentifier` [6]
    Uri,
    /// `registeredID` [8]
    RegisteredId,
    /// `otherName` [0] — value is `OID;type:value`
    OtherName,
    /// `directoryName` [4] — in a config the value names a section holding a DN
    DirName,
}

impl SanKind {
    /// Every kind, in the order a user is most likely to want them.
    pub const ALL: [SanKind; 7] = [
        SanKind::Dns,
        SanKind::Ip,
        SanKind::Email,
        SanKind::Uri,
        SanKind::RegisteredId,
        SanKind::OtherName,
        SanKind::DirName,
    ];

    /// The key OpenSSL's `subjectAltName` section uses for this kind.
    pub fn config_key(self) -> &'static str {
        match self {
            SanKind::Dns => "DNS",
            SanKind::Ip => "IP",
            SanKind::Email => "email",
            SanKind::Uri => "URI",
            SanKind::RegisteredId => "RID",
            SanKind::OtherName => "otherName",
            SanKind::DirName => "dirName",
        }
    }

    /// Human label, used by both front-ends.
    pub fn label(self) -> &'static str {
        match self {
            SanKind::Dns => "DNS",
            SanKind::Ip => "IP address",
            SanKind::Email => "Email",
            SanKind::Uri => "URI",
            SanKind::RegisteredId => "Registered ID",
            SanKind::OtherName => "Other name",
            SanKind::DirName => "Directory name",
        }
    }

    /// Parse an `[alt_names]` key. Case-insensitive: OpenSSL's own docs mix
    /// `email`/`Email` and real configs mix more than that.
    pub fn from_config_key(key: &str) -> Option<Self> {
        match key.to_ascii_lowercase().as_str() {
            "dns" => Some(SanKind::Dns),
            "ip" => Some(SanKind::Ip),
            "email" => Some(SanKind::Email),
            "uri" => Some(SanKind::Uri),
            "rid" => Some(SanKind::RegisteredId),
            "othername" => Some(SanKind::OtherName),
            "dirname" => Some(SanKind::DirName),
            _ => None,
        }
    }
}

/// One subject alternative name: a type and its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SanName {
    pub kind: SanKind,
    pub value: String,
}

impl SanName {
    pub fn new(kind: SanKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }
}

/// What the toolbox is able to read out of an existing OpenSSL config.
///
/// This is deliberately *not* `ConfigInputs`. `ConfigInputs` is a complete
/// description of a config this tool generates; a summary is a partial reading of
/// a config someone else wrote, where every field may be absent and anything the
/// toolbox does not model is reported rather than dropped. Nothing is ever
/// rewritten from a summary — see `ARCHITECTURE.md` §4.5.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSummary {
    pub common_name: Option<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
    pub organization: Option<String>,
    pub org_unit: Option<String>,
    pub email: Option<String>,
    pub key_size: Option<u32>,
    pub extended_key_usage: Option<String>,
    /// Every SAN the config declares, in file order, each with its RFC 5280 type.
    pub sans: Vec<SanName>,
    /// Every section header found, in file order — including ones the toolbox
    /// does not interpret, so the reader can see what is being preserved.
    pub sections: Vec<String>,
    /// Things worth a human's attention. Never fatal: a config the toolbox
    /// cannot fully read is still a config it must let you edit and save.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigInputs {
    pub common_name: String,
    pub country: String,
    pub state: String,
    pub locality: String,
    pub organization: String,
    pub org_unit: String,
    pub email: String,
    /// Additional SANs. The common name is always emitted as `DNS.1` on top.
    pub sans: Vec<SanName>,
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
pub struct TlsCipherScanResult {
    pub protocol: String,
    pub tested_cipher_count: usize,
    pub supported_ciphers: Vec<CipherInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCheckResult {
    pub host: String,
    pub port: u16,
    pub cipher: CipherInfo,
    pub cert_chain: Vec<CertDetails>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cert_chain_pem: Vec<String>,
    pub version_support: Vec<TlsVersionProbeResult>,
    pub cipher_scan: Vec<TlsCipherScanResult>,
    pub validation: Option<CertValidation>,
    /// True when the server's Certificate message order differed from the
    /// reconstructed leaf-first path in `cert_chain` (a server misconfiguration
    /// that can break strict, non-path-building TLS clients).
    #[serde(default)]
    pub chain_sent_out_of_order: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapAttribute {
    pub name: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfigCheckResult {
    pub host: String,
    pub port: u16,
    pub authentication: String,
    pub attributes: Vec<LdapAttribute>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

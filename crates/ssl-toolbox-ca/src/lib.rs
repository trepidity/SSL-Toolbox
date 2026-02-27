use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Trait for Certificate Authority plugins.
pub trait CaPlugin: Send + Sync {
    /// Human-readable name of this CA provider.
    fn name(&self) -> &str;

    /// List available certificate profiles/types.
    fn list_profiles(&self, debug: bool) -> Result<Vec<CertProfile>>;

    /// Submit a CSR for signing. Returns a request/order ID.
    fn submit_csr(&self, csr_pem: &str, options: &SubmitOptions, debug: bool) -> Result<String>;

    /// Collect/download a signed certificate by its request ID.
    fn collect_cert(&self, request_id: &str, format: CollectFormat, debug: bool) -> Result<String>;
}

/// A certificate profile offered by the CA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertProfile {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub terms: Vec<i32>,
}

/// Options for submitting a CSR.
#[derive(Debug, Clone)]
pub struct SubmitOptions {
    pub description: Option<String>,
    pub product_code: Option<String>,
    pub term_days: Option<i32>,
}

/// Format for collecting a signed certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectFormat {
    PemCert,
    PemChain,
    Pkcs7,
}

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
    ///
    /// Returns bytes rather than a `String` because one of the formats is DER.
    /// Treating that response as text corrupts it, and the corruption is silent
    /// — the file is written, it just no longer parses.
    fn collect_cert(&self, request_id: &str, format: CollectFormat, debug: bool)
    -> Result<Vec<u8>>;

    /// Find already-issued certificates matching a filter.
    ///
    /// Answers the question a request ID cannot: "what did we issue for this
    /// hostname, and is it still valid?" Results are deliberately lean — the
    /// list endpoint returns identifiers, not full records — with
    /// [`CaPlugin::certificate_details`] filling in the rest for one chosen row
    /// rather than for every row on the page.
    fn search_certificates(
        &self,
        filter: &CertificateFilter,
        debug: bool,
    ) -> Result<Vec<CertificateSummary>>;

    /// Full record for one certificate.
    fn certificate_details(&self, certificate_id: &str, debug: bool) -> Result<CertificateDetails>;

    /// Authenticate against the CA and go no further.
    ///
    /// Exists so a settings screen can answer "are these credentials right?"
    /// without an operation that has side effects at the CA. Listing profiles
    /// would also prove authentication, but it additionally requires a valid
    /// organisation ID — so a wrong org ID would read as a credential failure
    /// and send the user editing the wrong field.
    fn test_auth(&self, debug: bool) -> Result<()>;
}

/// A certificate profile offered by the CA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertProfile {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub terms: Vec<i32>,
}

/// What to match when searching a CA's issued certificates.
///
/// Every field is optional and empty means "do not filter"; an all-empty filter
/// lists everything the account can see, one page at a time.
#[derive(Debug, Clone)]
pub struct CertificateFilter {
    pub common_name: Option<String>,
    pub subject_alternative_name: Option<String>,
    pub serial_number: Option<String>,
    /// Vendor-specific status label, e.g. Sectigo's `Issued` / `Revoked`.
    pub status: Option<String>,
    /// Restrict to one certificate profile.
    pub profile_id: Option<String>,
    /// Page size. Capped by the plugin to whatever its API allows.
    pub size: Option<u32>,
    /// Zero-based offset of the first result.
    pub position: Option<u32>,
    /// Fill in status and dates for every row, even when that costs one extra
    /// request per result.
    ///
    /// On by default because a results list without them cannot answer "is this
    /// the live certificate?", which is the question a search is asked. Turn it
    /// off for a large page, or when only the identifiers are wanted.
    pub include_dates: bool,
}

impl Default for CertificateFilter {
    fn default() -> Self {
        Self {
            common_name: None,
            subject_alternative_name: None,
            serial_number: None,
            status: None,
            profile_id: None,
            size: None,
            position: None,
            include_dates: true,
        }
    }
}

/// One row of a certificate search.
///
/// `id` is the same identifier [`CaPlugin::collect_cert`] takes, so a search
/// result can be downloaded without the operator copying anything by hand.
///
/// Status and dates are optional because a CA's list endpoint may not return
/// them. They are the columns that decide whether a result is the certificate
/// the operator is looking for, so a plugin that can fill them in should — see
/// [`CertificateFilter::include_dates`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertificateSummary {
    pub id: String,
    pub common_name: String,
    pub subject_alternative_names: Vec<String>,
    pub serial_number: String,
    pub status: Option<String>,
    pub requested: Option<String>,
    pub expires: Option<String>,
}

/// The full record behind a search result.
///
/// Fields are optional because this is a vendor payload: an account, profile, or
/// API version that omits one should render a gap, not fail the whole lookup.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertificateDetails {
    pub id: String,
    pub common_name: String,
    pub subject_alternative_names: Vec<String>,
    pub serial_number: String,
    pub status: Option<String>,
    pub profile: Option<String>,
    pub term_days: Option<i32>,
    pub requested: Option<String>,
    pub expires: Option<String>,
    pub requester: Option<String>,
    pub comments: Option<String>,
    pub key_algorithm: Option<String>,
}

/// Options for submitting a CSR.
#[derive(Debug, Clone)]
pub struct SubmitOptions {
    pub description: Option<String>,
    pub product_code: Option<String>,
    pub term_days: Option<i32>,
}

/// What to download when collecting an issued certificate.
///
/// These mirror the choices a CA console offers, because an operator who picked
/// "Certificate (w/ chain), PEM encoded" in the web UI needs the same artifact
/// here. Naming them by their *content* rather than by a vendor token keeps the
/// trait vendor-neutral: each plugin maps these to whatever its API calls them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectFormat {
    /// The leaf certificate alone.
    CertificateOnlyPem,
    /// The leaf followed by its issuer.
    CertificateIssuerAfterPem,
    /// The leaf followed by the full chain — what a web server usually wants.
    CertificateChainPem,
    /// PKCS#7, DER encoded. **Binary** — see [`CollectFormat::is_binary`].
    Pkcs7Der,
    /// PKCS#7, PEM encoded.
    Pkcs7Pem,
    /// Intermediates and root only, leaf excluded.
    IntermediatesRootPem,
    /// Root and intermediates only, in the reverse order.
    RootIntermediatesPem,
}

impl CollectFormat {
    /// Every format, in the order a UI should offer them.
    pub const ALL: [CollectFormat; 7] = [
        Self::CertificateOnlyPem,
        Self::CertificateIssuerAfterPem,
        Self::CertificateChainPem,
        Self::Pkcs7Der,
        Self::Pkcs7Pem,
        Self::IntermediatesRootPem,
        Self::RootIntermediatesPem,
    ];

    /// Stable token used on the command line and across the IPC boundary.
    pub fn token(self) -> &'static str {
        match self {
            Self::CertificateOnlyPem => "cert",
            Self::CertificateIssuerAfterPem => "cert-issuer-after",
            Self::CertificateChainPem => "chain",
            Self::Pkcs7Der => "pkcs7",
            Self::Pkcs7Pem => "pkcs7-pem",
            Self::IntermediatesRootPem => "intermediates",
            Self::RootIntermediatesPem => "root-first",
        }
    }

    /// Wording matching what the CA console shows, so the two agree on screen.
    pub fn label(self) -> &'static str {
        match self {
            Self::CertificateOnlyPem => "Certificate only, PEM encoded",
            Self::CertificateIssuerAfterPem => "Certificate (w/ issuer after), PEM encoded",
            Self::CertificateChainPem => "Certificate (w/ chain), PEM encoded",
            Self::Pkcs7Der => "PKCS#7",
            Self::Pkcs7Pem => "PKCS#7, PEM encoded",
            Self::IntermediatesRootPem => "Intermediate(s)/Root only, PEM encoded",
            Self::RootIntermediatesPem => "Root/Intermediate(s) only, PEM encoded",
        }
    }

    /// True when the response is raw bytes that must not be treated as text.
    ///
    /// Decoding DER as UTF-8 and writing the result back out silently corrupts
    /// it — the bytes that fail to decode become replacement characters and the
    /// file no longer parses as PKCS#7.
    pub fn is_binary(self) -> bool {
        matches!(self, Self::Pkcs7Der)
    }

    /// Default file extension for this format.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Pkcs7Der | Self::Pkcs7Pem => "p7b",
            _ => "pem",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        let normalized = value.trim().to_lowercase();
        Self::ALL
            .into_iter()
            .find(|format| format.token() == normalized)
            // `pem` was the old spelling of "leaf only"; keep it working.
            .or(match normalized.as_str() {
                "pem" => Some(Self::CertificateOnlyPem),
                _ => None,
            })
    }
}

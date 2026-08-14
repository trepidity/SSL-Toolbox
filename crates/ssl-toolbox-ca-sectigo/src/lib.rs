use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use ssl_toolbox_ca::{
    CaPlugin, CertProfile, CertificateDetails, CertificateFilter, CertificateSummary,
    CollectFormat, SubmitOptions,
};
use std::env;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Results per page when the caller does not say.
const DEFAULT_PAGE_SIZE: u32 = 25;
/// Sectigo rejects a larger page rather than truncating one.
const MAX_PAGE_SIZE: u32 = 200;

/// Hard ceiling on any single CA request.
///
/// ARCHITECTURE.md §12.10 makes timeouts non-optional. A CA API call is allowed
/// longer than a TLS handshake — enrolment does real work server-side — but not
/// unbounded, which is what "no timeout" meant before: a stalled connection hung
/// the desktop app with no way out but force-quitting it.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a fetched access token is reused.
///
/// Sectigo's tokens live far longer than this; the short window is deliberate,
/// since the point is to collapse the burst of calls a single search makes, not
/// to hold credentials in memory across an idle session. Without it, filling in
/// status and expiry for a 25-row page costs 50 requests instead of 26.
const TOKEN_LIFETIME: Duration = Duration::from_secs(240);

/// Detail lookups issued at once while enriching a page of search results.
///
/// Sized to shorten a 25-row page from 25 sequential round trips to about four,
/// without opening enough sockets to look like abuse to the CA.
const ENRICH_CONCURRENCY: usize = 8;

fn default_api_base() -> String {
    "https://admin.enterprise.sectigo.com".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectigoConfig {
    #[serde(default = "default_api_base")]
    pub api_base: String,
    #[serde(default)]
    pub org_id: String,
    #[serde(default)]
    pub product_code: String,
    #[serde(default)]
    pub token_url: String,
}

impl Default for SectigoConfig {
    fn default() -> Self {
        Self {
            api_base: default_api_base(),
            org_id: String::new(),
            product_code: String::new(),
            token_url: String::new(),
        }
    }
}

pub struct SectigoPlugin {
    api_base: String,
    org_id: String,
    default_product_code: String,
    scm_client_id: String,
    scm_client_secret: String,
    scm_token_url: String,
    /// Access token reused across the calls of one operation. See [`TOKEN_LIFETIME`].
    cached_token: Mutex<Option<(String, Instant)>>,
}

impl SectigoPlugin {
    /// Create and configure a SectigoPlugin.
    ///
    /// Credentials arrive as arguments rather than being read from the
    /// environment here. Deciding *where* a credential comes from — environment
    /// variable, encrypted vault, or neither — is orchestration policy, and
    /// ARCHITECTURE.md §2.5 puts that in `ssl-toolbox-ops`. This crate stays
    /// what it should be: an API client that is handed an identity and uses it.
    pub fn configure_with_config(
        config: &SectigoConfig,
        client_id: &str,
        client_secret: &str,
        debug: bool,
    ) -> Result<Box<dyn CaPlugin>> {
        let scm_client_id = client_id.to_string();
        let scm_client_secret = client_secret.to_string();

        let scm_token_url = env::var("SCM_TOKEN_URL").unwrap_or_else(|_| config.token_url.clone());
        if scm_token_url.is_empty() {
            return Err(anyhow!(
                "No CA token URL configured. Set it in Settings, in .ssl-toolbox/sectigo.json, or as SCM_TOKEN_URL."
            ));
        }

        let api_base = env::var("SECTIGO_API_BASE").unwrap_or_else(|_| config.api_base.clone());
        let org_id = env::var("SECTIGO_ORG_ID").unwrap_or_else(|_| config.org_id.clone());
        let default_product_code =
            env::var("SECTIGO_PRODUCT_CODE").unwrap_or_else(|_| config.product_code.clone());

        if debug {
            println!("DEBUG: Configuring Sectigo plugin");
            println!("  API Base: {}", api_base);
            println!("  Token URL: {}", scm_token_url);
            println!("  Client ID length: {}", scm_client_id.len());
            println!(
                "  Organization ID configured: {}",
                if org_id.is_empty() { "No" } else { "Yes" }
            );
        }

        Ok(Box::new(SectigoPlugin {
            api_base,
            org_id,
            default_product_code,
            scm_client_id,
            scm_client_secret,
            scm_token_url,
            cached_token: Mutex::new(None),
        }))
    }

    /// An HTTP client with a timeout, which every call in this crate must use.
    fn http(&self) -> Result<reqwest::blocking::Client> {
        reqwest::blocking::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("Failed to build the CA HTTP client")
    }

    /// A bearer token, reusing a recent one rather than re-authenticating.
    fn token(&self, debug: bool) -> Result<String> {
        {
            let cache = self.cached_token.lock().expect("token cache poisoned");
            if let Some((token, fetched_at)) = cache.as_ref()
                && fetched_at.elapsed() < TOKEN_LIFETIME
            {
                return Ok(token.clone());
            }
        }

        // `get_token`, not `token`: this *is* the cache-miss path, and calling
        // back into the cache would recurse forever.
        let token = self.get_token(debug)?;
        *self.cached_token.lock().expect("token cache poisoned") =
            Some((token.clone(), Instant::now()));
        Ok(token)
    }

    fn get_token(&self, debug: bool) -> Result<String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("Failed to build the token HTTP client")?;

        if debug {
            println!("  Token URL: {}", self.scm_token_url);
            println!("  Client ID length: {}", self.scm_client_id.len());
        }

        let response = client
            .post(&self.scm_token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &self.scm_client_id),
                ("client_secret", &self.scm_client_secret),
            ])
            .send()
            .context("Failed to send token request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .unwrap_or_else(|_| "Could not read body".to_string());
            if debug {
                println!("  Error Status: {}", status);
                println!("  Error Body: {}", body);
            }
            return Err(anyhow!("HTTP status {} - {}", status, body));
        }

        let token_res: TokenResponse = response.json().context("Failed to parse token response")?;
        Ok(token_res.access_token)
    }

    /// Fill in status and dates for rows the list endpoint left bare.
    ///
    /// One detail request per row, run in bounded batches. A row that fails is
    /// left partly blank rather than failing the search: a page of results with
    /// one missing expiry column is far more useful than an error, and the
    /// operator can still open that row to see what went wrong.
    fn fill_in_dates(&self, summaries: &mut [CertificateSummary], debug: bool) {
        let missing: Vec<usize> = summaries
            .iter()
            .enumerate()
            .filter(|(_, summary)| summary.expires.is_none() || summary.status.is_none())
            .map(|(index, _)| index)
            .collect();

        if missing.is_empty() {
            return;
        }
        if debug {
            println!(
                "DEBUG: filling in dates for {} of {} rows",
                missing.len(),
                summaries.len()
            );
        }

        for batch in missing.chunks(ENRICH_CONCURRENCY) {
            let fetched: Vec<(usize, Option<CertificateDetails>)> = std::thread::scope(|scope| {
                let handles: Vec<_> = batch
                    .iter()
                    .map(|&index| {
                        let id = summaries[index].id.clone();
                        scope.spawn(move || (index, self.certificate_details(&id, false).ok()))
                    })
                    .collect();
                handles
                    .into_iter()
                    .filter_map(|handle| handle.join().ok())
                    .collect()
            });

            for (index, details) in fetched {
                let Some(details) = details else { continue };
                let summary = &mut summaries[index];
                summary.status = summary.status.take().or(details.status);
                summary.requested = summary.requested.take().or(details.requested);
                summary.expires = summary.expires.take().or(details.expires);
                if summary.serial_number.is_empty() {
                    summary.serial_number = details.serial_number;
                }
            }
        }
    }

    fn strip_csr(csr: &str) -> String {
        csr.lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("")
    }
}

impl CaPlugin for SectigoPlugin {
    fn name(&self) -> &str {
        "Sectigo"
    }

    fn test_auth(&self, debug: bool) -> Result<()> {
        // Deliberately bypasses the token cache: "test connection" has to prove
        // the credentials work *now*, not that they worked four minutes ago.
        self.get_token(debug).map(|_| ())
    }

    fn search_certificates(
        &self,
        filter: &CertificateFilter,
        debug: bool,
    ) -> Result<Vec<CertificateSummary>> {
        let token = self.token(debug)?;
        let client = self.http()?;

        let mut query: Vec<(&str, String)> = Vec::new();
        let mut push = |key: &'static str, value: &Option<String>| {
            if let Some(value) = value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
                query.push((key, value.to_string()));
            }
        };
        push("commonName", &filter.common_name);
        push("subjectAlternativeName", &filter.subject_alternative_name);
        push("serialNumber", &filter.serial_number);
        push("status", &filter.status);
        push("sslTypeId", &filter.profile_id);

        // The API caps a page; asking for more is an error rather than a
        // truncation, so the cap is applied here instead of being discovered.
        query.push((
            "size",
            filter
                .size
                .unwrap_or(DEFAULT_PAGE_SIZE)
                .min(MAX_PAGE_SIZE)
                .to_string(),
        ));
        query.push(("position", filter.position.unwrap_or(0).to_string()));

        // The organisation scopes the search when one is configured. Without it
        // the account's full visibility applies, which is a valid search.
        if !self.org_id.is_empty() {
            query.push(("orgId", self.org_id.clone()));
        }

        let url = format!("{}/api/ssl/v1", self.api_base);
        if debug {
            println!("DEBUG: Searching certificates:");
            println!("  URL: {}", url);
            println!("  Query: {:?}", query);
        }

        let response = client
            .get(&url)
            .query(&query)
            .bearer_auth(&token)
            .send()
            .context("Failed to search certificates")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .unwrap_or_else(|_| "Could not read body".to_string());
            return Err(anyhow!("Certificate search failed: {} - {}", status, body));
        }

        let body = response.text().context("Failed to read search response")?;
        let rows: Vec<SectigoSslListItem> = serde_json::from_str(&body)
            .with_context(|| format!("Failed to parse search response. Body: {body}"))?;

        let mut summaries: Vec<CertificateSummary> = rows
            .into_iter()
            .map(SectigoSslListItem::into_summary)
            .collect();

        if filter.include_dates {
            self.fill_in_dates(&mut summaries, debug);
        }

        Ok(summaries)
    }

    fn certificate_details(&self, certificate_id: &str, debug: bool) -> Result<CertificateDetails> {
        let token = self.token(debug)?;
        let client = self.http()?;

        let url = format!("{}/api/ssl/v1/{}", self.api_base, certificate_id);
        if debug {
            println!("DEBUG: Fetching certificate details:");
            println!("  URL: {}", url);
        }

        let response = client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .context("Failed to fetch certificate details")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .unwrap_or_else(|_| "Could not read body".to_string());
            return Err(anyhow!(
                "Could not read certificate {certificate_id}: {} - {}",
                status,
                body
            ));
        }

        let body = response.text().context("Failed to read details response")?;
        let record: SectigoSslRecord = serde_json::from_str(&body)
            .with_context(|| format!("Failed to parse certificate details. Body: {body}"))?;

        Ok(record.into_details())
    }

    fn list_profiles(&self, debug: bool) -> Result<Vec<CertProfile>> {
        if self.org_id.is_empty() {
            return Err(anyhow!(
                "No organisation ID configured. Set it in Settings, in .ssl-toolbox/sectigo.json, or as SECTIGO_ORG_ID."
            ));
        }

        println!("Fetching available SSL certificate types from Sectigo...");
        let token = self.token(debug)?;

        let client = self.http()?;

        let url = format!("{}/api/ssl/v2/types?orgId={}", self.api_base, self.org_id);

        let response = client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .context("Failed to fetch SSL profiles")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .unwrap_or_else(|_| "Could not read body".to_string());
            if debug {
                println!("  Error Status: {}", status);
                println!("  Error Body: {}", body);
            }
            return Err(anyhow!(
                "Failed to fetch SSL profiles: {} - {}",
                status,
                body
            ));
        }

        let body_text = response.text().context("Failed to read response body")?;

        let profiles: Vec<SectigoSslProfile> = serde_json::from_str(&body_text).context(
            format!("Failed to parse SSL profiles response. Body: {}", body_text),
        )?;

        Ok(profiles
            .into_iter()
            .map(|p| CertProfile {
                id: p.id.to_string(),
                name: p.name,
                description: p.description,
                terms: p.terms,
            })
            .collect())
    }

    fn submit_csr(&self, csr_pem: &str, options: &SubmitOptions, debug: bool) -> Result<String> {
        let stripped_csr = Self::strip_csr(csr_pem);

        println!("Authenticating with Sectigo SCM...");
        let token = self.token(debug)?;

        let client = self.http()?;

        let cert_type = options
            .product_code
            .clone()
            .unwrap_or_else(|| self.default_product_code.clone());
        let org_id = self.org_id.clone();

        // Fetch profiles to get available terms
        let profiles = self.list_profiles(debug)?;
        let profile = profiles
            .iter()
            .find(|p| p.id == cert_type)
            .ok_or_else(|| anyhow!("Could not find SSL profile with ID: {}", cert_type))?;

        let term_days = if let Some(t) = options.term_days {
            t
        } else {
            *profile
                .terms
                .iter()
                .max()
                .ok_or_else(|| anyhow!("No terms available for profile: {}", profile.name))?
        };

        if debug {
            println!(
                "DEBUG: Selected profile: {} (ID: {})",
                profile.name, profile.id
            );
            println!("DEBUG: Available terms: {:?}", profile.terms);
            println!("DEBUG: Selected term: {} days", term_days);
        }

        let payload = EnrollRequest {
            cert_type,
            csr: stripped_csr,
            org_id,
            term: term_days,
        };

        if debug {
            println!("DEBUG: Sectigo Enrollment Request:");
            println!("  URL: {}/api/ssl/v1/enroll", self.api_base);
            println!(
                "  Payload: {}",
                serde_json::to_string_pretty(&payload).unwrap_or_default()
            );
        }

        let response = client
            .post(format!("{}/api/ssl/v1/enroll", self.api_base))
            .header("Content-Type", "application/json")
            .bearer_auth(&token)
            .json(&payload)
            .send()
            .context("Failed to send enrollment request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .unwrap_or_else(|_| "Could not read body".to_string());
            println!("  Enrollment Error Status: {}", status);
            println!("  Enrollment Error Body: {}", body);
            return Err(anyhow!("Enrollment failed: {} - {}", status, body));
        }

        let enroll_res: EnrollResponse = response.json()?;
        let ssl_id = enroll_res
            .ssl_id
            .context("No sslId returned from enrollment")?;

        println!("Enrollment successful. SSL ID: {}", ssl_id);

        // Attach description if provided
        if let Some(desc) = &options.description
            && !desc.is_empty()
        {
            println!("Attaching description to certificate...");
            let update_payload = UpdateSslRequest {
                ssl_id,
                comments: desc.clone(),
            };
            let response = client
                .put(format!("{}/api/ssl/v1", self.api_base))
                .header("Content-Type", "application/json")
                .bearer_auth(&token)
                .json(&update_payload)
                .send()
                .context("Failed to attach description")?;

            if !response.status().is_success() {
                println!(
                    "  Warning: Failed to attach description: {}",
                    response.status()
                );
            } else {
                println!("  Description attached successfully.");
            }
        }

        Ok(ssl_id.to_string())
    }

    fn collect_cert(
        &self,
        request_id: &str,
        format: CollectFormat,
        debug: bool,
    ) -> Result<Vec<u8>> {
        let token = self.token(debug)?;

        let client = self.http()?;

        let url = format!(
            "{}/api/ssl/v1/collect/{}?format={}",
            self.api_base,
            request_id,
            sectigo_format_token(format)
        );

        if debug {
            println!("DEBUG: Collecting certificate:");
            println!("  URL: {}", url);
        }

        let response = client
            .get(&url)
            .bearer_auth(&token)
            .send()?
            .error_for_status()
            .context("Failed to collect certificate")?;

        // `.bytes()`, not `.text()`: the PKCS#7 DER format is binary, and
        // lossy UTF-8 decoding would replace bytes rather than fail loudly.
        Ok(response.bytes()?.to_vec())
    }
}

/// Map a requested artifact to Sectigo's `format` query value.
///
/// These tokens are Sectigo's, not ours, and they are not guessable from their
/// names — `x509CO` is *certificate only* despite reading like a chain, and
/// `x509IOR` reverses the order of `x509IO`. The authoritative list is the
/// `valid_formats` enumeration in Sectigo's own client libraries:
///
/// ```text
/// x509    X509, Base64 encoded              pem     Certificate (w/ chain), PEM encoded
/// x509CO  X509 Certificate only, Base64     pemco   Certificate only, PEM encoded
/// x509IO  X509 Intermediates/root only      pemia   Certificate (w/ issuer after), PEM
/// x509IOR X509 Intermediates/root, reverse  base64  PKCS#7, Base64 encoded
/// bin     PKCS#7, binary
/// ```
///
/// The seven mapped here are the seven the SCM console's Retrieve menu offers,
/// so what an operator picks in the browser and what they pick here agree.
fn sectigo_format_token(format: CollectFormat) -> &'static str {
    match format {
        CollectFormat::CertificateOnlyPem => "pemco",
        CollectFormat::CertificateIssuerAfterPem => "pemia",
        CollectFormat::CertificateChainPem => "pem",
        CollectFormat::Pkcs7Der => "bin",
        CollectFormat::Pkcs7Pem => "base64",
        CollectFormat::IntermediatesRootPem => "x509IO",
        CollectFormat::RootIntermediatesPem => "x509IOR",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sectigo's list endpoint returns identifiers only, and the desktop search
    /// screen renders exactly these fields. Parsing is asserted against a
    /// committed capture of the documented response rather than against
    /// re-serializing our own structs, which would prove nothing.
    #[test]
    fn a_search_response_parses_into_rows_the_ui_can_render() {
        let body = include_str!("../tests/fixtures/ssl-list.json");
        let rows: Vec<SectigoSslListItem> =
            serde_json::from_str(body).expect("the documented list shape must parse");
        let summaries: Vec<_> = rows
            .into_iter()
            .map(SectigoSslListItem::into_summary)
            .collect();

        assert_eq!(summaries.len(), 2);
        // The ID is what Collect takes, so it must survive as the string form of
        // the numeric sslId — not as a debug rendering of the JSON number.
        assert_eq!(summaries[0].id, "1234567");
        assert_eq!(summaries[0].common_name, "svc.example.test");
        assert_eq!(
            summaries[0].subject_alternative_names,
            ["svc.example.test", "svc-alt.example.test"]
        );
        assert_eq!(summaries[0].serial_number, "00a1b2c3d4e5f60718");

        // Sectigo omits `subjectAlternativeNames` for single-name certificates.
        // A missing array must read as "none", not fail the whole page.
        assert!(summaries[1].subject_alternative_names.is_empty());
        assert_eq!(summaries[1].id, "7654321");
    }

    #[test]
    fn a_details_response_parses_the_fields_an_operator_decides_on() {
        let body = include_str!("../tests/fixtures/ssl-details.json");
        let record: SectigoSslRecord =
            serde_json::from_str(body).expect("the documented details shape must parse");
        let details = record.into_details();

        assert_eq!(details.id, "1234567");
        assert_eq!(details.status.as_deref(), Some("Issued"));
        assert_eq!(details.expires.as_deref(), Some("2027-01-15"));
        assert_eq!(details.requested.as_deref(), Some("2026-01-15"));
        assert_eq!(details.term_days, Some(365));
        // `certType` is a nested object; the profile name is what identifies it
        // to a human, and flattening it wrong yields a blank column.
        assert_eq!(details.profile.as_deref(), Some("OV Multi-Domain SSL"));
        assert_eq!(details.requester.as_deref(), Some("jared@example.test"));
        assert_eq!(details.key_algorithm.as_deref(), Some("RSA"));
    }

    /// An account or API version that omits optional fields must still yield a
    /// usable record — the alternative is a lookup that fails on a technicality.
    #[test]
    fn a_sparse_details_response_still_identifies_the_certificate() {
        let record: SectigoSslRecord =
            serde_json::from_str(r#"{"sslId": 42, "commonName": "bare.example.test"}"#)
                .expect("a minimal record must parse");
        let details = record.into_details();

        assert_eq!(details.id, "42");
        assert_eq!(details.common_name, "bare.example.test");
        assert_eq!(details.status, None);
        assert_eq!(details.expires, None);
        assert!(details.subject_alternative_names.is_empty());
    }

    /// The tokens are a vendor wire contract, and getting one wrong fails in the
    /// worst possible way: the request succeeds and returns the wrong artifact.
    /// A previous mapping sent `x509CO` for "chain", so every chain download was
    /// silently a bare leaf certificate, and sent `pkcs7`, which is not a value
    /// Sectigo accepts at all.
    ///
    /// Expectations come from Sectigo's published `valid_formats` list, not from
    /// the function under test.
    #[test]
    fn collect_formats_map_to_the_tokens_sectigo_documents() {
        let expected = [
            (CollectFormat::CertificateOnlyPem, "pemco"),
            (CollectFormat::CertificateIssuerAfterPem, "pemia"),
            (CollectFormat::CertificateChainPem, "pem"),
            (CollectFormat::Pkcs7Der, "bin"),
            (CollectFormat::Pkcs7Pem, "base64"),
            (CollectFormat::IntermediatesRootPem, "x509IO"),
            (CollectFormat::RootIntermediatesPem, "x509IOR"),
        ];

        for (format, token) in expected {
            assert_eq!(
                sectigo_format_token(format),
                token,
                "{:?} must request Sectigo's `{token}` format",
                format
            );
        }
    }

    #[test]
    fn only_the_der_pkcs7_format_is_treated_as_binary() {
        // Getting this wrong writes a PKCS#7 file full of U+FFFD.
        for format in CollectFormat::ALL {
            assert_eq!(
                format.is_binary(),
                sectigo_format_token(format) == "bin",
                "{:?} disagrees about whether its response is binary",
                format
            );
        }
    }
}

/// A row from `GET /api/ssl/v1`.
///
/// The list endpoint returns identifiers only — no status, no expiry — which is
/// why a detail lookup exists separately.
#[derive(Deserialize)]
struct SectigoSslListItem {
    #[serde(rename = "sslId")]
    ssl_id: i64,
    #[serde(rename = "commonName", default)]
    common_name: String,
    #[serde(rename = "subjectAlternativeNames", default)]
    subject_alternative_names: Vec<String>,
    #[serde(rename = "serialNumber", default)]
    serial_number: String,
    // Read opportunistically. Sectigo's list response is documented as
    // identifiers only, but an account or API version that does return these
    // saves a detail call per row — so take them when offered rather than
    // asking again for something already in hand.
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    requested: Option<String>,
    #[serde(default)]
    expires: Option<String>,
}

impl SectigoSslListItem {
    fn into_summary(self) -> CertificateSummary {
        CertificateSummary {
            id: self.ssl_id.to_string(),
            common_name: self.common_name,
            subject_alternative_names: self.subject_alternative_names,
            serial_number: self.serial_number,
            status: self.status,
            requested: self.requested,
            expires: self.expires,
        }
    }
}

/// The full record from `GET /api/ssl/v1/{sslId}`.
///
/// Every field beyond the identifier is optional: this is a vendor payload, and
/// an account or API version that omits one should leave a gap in the UI rather
/// than fail the lookup outright.
#[derive(Deserialize)]
struct SectigoSslRecord {
    #[serde(rename = "sslId")]
    ssl_id: i64,
    #[serde(rename = "commonName", default)]
    common_name: String,
    #[serde(rename = "subjectAlternativeNames", default)]
    subject_alternative_names: Vec<String>,
    #[serde(rename = "serialNumber", default)]
    serial_number: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(rename = "certType", default)]
    cert_type: Option<SectigoCertType>,
    #[serde(default)]
    term: Option<i32>,
    #[serde(default)]
    requested: Option<String>,
    #[serde(default)]
    expires: Option<String>,
    #[serde(default)]
    requester: Option<String>,
    #[serde(default)]
    comments: Option<String>,
    #[serde(rename = "keyAlgorithm", default)]
    key_algorithm: Option<String>,
}

#[derive(Deserialize)]
struct SectigoCertType {
    #[serde(default)]
    name: Option<String>,
}

impl SectigoSslRecord {
    fn into_details(self) -> CertificateDetails {
        CertificateDetails {
            id: self.ssl_id.to_string(),
            common_name: self.common_name,
            subject_alternative_names: self.subject_alternative_names,
            serial_number: self.serial_number,
            status: self.status,
            profile: self.cert_type.and_then(|value| value.name),
            term_days: self.term,
            requested: self.requested,
            expires: self.expires,
            requester: self.requester,
            comments: self.comments,
            key_algorithm: self.key_algorithm,
        }
    }
}

// Internal Sectigo API types

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize, Clone)]
struct SectigoSslProfile {
    id: i32,
    name: String,
    #[serde(default)]
    description: Option<String>,
    terms: Vec<i32>,
    #[allow(dead_code)]
    #[serde(rename = "keyTypes")]
    key_types: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(rename = "useSecondaryOrgName")]
    use_secondary_org_name: bool,
}

#[derive(Serialize)]
struct EnrollRequest {
    #[serde(rename = "certType")]
    cert_type: String,
    csr: String,
    #[serde(rename = "orgId")]
    org_id: String,
    term: i32,
}

#[derive(Serialize)]
struct UpdateSslRequest {
    #[serde(rename = "sslId")]
    ssl_id: i64,
    comments: String,
}

#[derive(Deserialize)]
struct EnrollResponse {
    #[serde(rename = "sslId")]
    ssl_id: Option<i64>,
}

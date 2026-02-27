use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use ssl_toolbox_ca::{CaPlugin, CertProfile, CollectFormat, SubmitOptions};
use std::env;

fn default_api_base() -> String {
    "https://cert-manager.com".to_string()
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
}

impl SectigoPlugin {
    /// Create and configure a SectigoPlugin from environment variables only (backward compat).
    pub fn configure(debug: bool) -> Result<Box<dyn CaPlugin>> {
        Self::configure_with_config(&SectigoConfig::default(), debug)
    }

    /// Create and configure a SectigoPlugin from a config struct.
    /// Environment variables override config values where set.
    pub fn configure_with_config(config: &SectigoConfig, debug: bool) -> Result<Box<dyn CaPlugin>> {
        let scm_client_id =
            env::var("SCM_CLIENT_ID").context("SCM_CLIENT_ID not set. Check .env file.")?;
        let scm_client_secret =
            env::var("SCM_CLIENT_SECRET").context("SCM_CLIENT_SECRET not set. Check .env file.")?;

        let scm_token_url = env::var("SCM_TOKEN_URL").unwrap_or_else(|_| config.token_url.clone());
        if scm_token_url.is_empty() {
            return Err(anyhow!(
                "SCM_TOKEN_URL not set. Set it in .env or .ssl-toolbox/sectigo.json"
            ));
        }

        let api_base = env::var("SECTIGO_API_BASE").unwrap_or_else(|_| config.api_base.clone());
        let org_id = env::var("SECTIGO_ORG_ID").unwrap_or_else(|_| config.org_id.clone());
        let default_product_code =
            env::var("SECTIGO_PRODUCT_CODE").unwrap_or_else(|_| config.product_code.clone());

        if debug {
            println!("DEBUG: Configuring Sectigo plugin");
            println!("  Token URL: {}", scm_token_url);
            println!("  Client ID length: {}", scm_client_id.len());
        }

        Ok(Box::new(SectigoPlugin {
            api_base,
            org_id,
            default_product_code,
            scm_client_id,
            scm_client_secret,
            scm_token_url,
        }))
    }

    fn get_token(&self, debug: bool) -> Result<String> {
        let client = reqwest::blocking::Client::new();

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

    fn list_profiles(&self, debug: bool) -> Result<Vec<CertProfile>> {
        println!("Fetching available SSL certificate types from Sectigo...");
        let token = self.get_token(debug)?;

        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let url = format!(
            "{}/api/ssl/v2/types?organizationId={}",
            self.api_base, self.org_id
        );

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
        let token = self.get_token(debug)?;

        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

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
            .post(&format!("{}/api/ssl/v1/enroll", self.api_base))
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
        if let Some(desc) = &options.description {
            if !desc.is_empty() {
                println!("Attaching description to certificate...");
                let update_payload = UpdateSslRequest {
                    ssl_id,
                    comments: desc.clone(),
                };
                let response = client
                    .put(&format!("{}/api/ssl/v1", self.api_base))
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
        }

        Ok(ssl_id.to_string())
    }

    fn collect_cert(&self, request_id: &str, format: CollectFormat, debug: bool) -> Result<String> {
        let token = self.get_token(debug)?;

        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let format_str = match format {
            CollectFormat::PemCert => "x509",
            CollectFormat::PemChain => "x509CO",
            CollectFormat::Pkcs7 => "pkcs7",
        };

        let url = format!(
            "{}/api/ssl/v1/collect/{}?format={}",
            self.api_base, request_id, format_str
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

        let cert_content = response.text()?;
        Ok(cert_content)
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

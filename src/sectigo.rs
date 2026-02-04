use serde::{Deserialize, Serialize};
use anyhow::{Result, Context, anyhow};
use std::fs;
use std::env;

pub struct SectigoConfig {
    pub api_base: String,
    pub org_id: String,
    pub product_code: String,
    pub term: i32,
    pub scm_client_id: String,
    pub scm_client_secret: String,
    pub scm_token_url: String,
}

impl Default for SectigoConfig {
    fn default() -> Self {
        Self {
            api_base: env::var("SECTIGO_API_BASE").unwrap_or_else(|_| "https://cert-manager.com".to_string()),
            org_id: env::var("SECTIGO_ORG_ID").unwrap_or_else(|_| "6377".to_string()),
            product_code: env::var("SECTIGO_PRODUCT_CODE").unwrap_or_else(|_| "4491".to_string()),
            term: env::var("SECTIGO_TERM").ok().and_then(|t| t.parse().ok()).unwrap_or(190),
            scm_client_id: env::var("SCM_CLIENT_ID").unwrap_or_default(),
            scm_client_secret: env::var("SCM_CLIENT_SECRET").unwrap_or_default(),
            scm_token_url: env::var("SCM_TOKEN_URL").unwrap_or_default(),
        }
    }
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

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize, Clone)]
pub struct SslProfile {
    pub id: i32,  // API returns integer
    pub name: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub description: Option<String>,
    pub terms: Vec<i32>,
    #[allow(dead_code)]
    #[serde(rename = "keyTypes")]
    pub key_types: Option<serde_json::Value>,  // Complex nested structure, not needed for display
    #[allow(dead_code)]
    #[serde(rename = "useSecondaryOrgName")]
    pub use_secondary_org_name: bool,
}

fn get_scm_token(config: &SectigoConfig, debug: bool) -> Result<String> {
    let client = reqwest::blocking::Client::new();
    
    if debug {
        println!("  URL: {}", config.scm_token_url);
        println!("  Client ID length: {}", config.scm_client_id.len());
    }
    
    let response = client.post(&config.scm_token_url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &config.scm_client_id),
            ("client_secret", &config.scm_client_secret),
        ])
        .send()
        .context("Failed to send token request")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_else(|_| "Could not read body".to_string());
        println!("  Error Status: {}", status);
        println!("  Error Body: {}", body);
        return Err(anyhow!("HTTP status {} - {}", status, body));
    }

    let token_res: TokenResponse = response.json().context("Failed to parse token response")?;
    Ok(token_res.access_token)
}

pub fn list_ssl_profiles(config: &SectigoConfig, debug: bool) -> Result<Vec<SslProfile>> {
    println!("Fetching available SSL certificate types from Sectigo...");
    let token = get_scm_token(config, debug)?;

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let url = format!("{}/api/ssl/v2/types?organizationId={}", config.api_base, config.org_id);
    
    let response = client.get(&url)
        .bearer_auth(&token)
        .send()
        .context("Failed to fetch SSL profiles")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_else(|_| "Could not read body".to_string());
        println!("  Error Status: {}", status);
        println!("  Error Body: {}", body);
        return Err(anyhow!("Failed to fetch SSL profiles: {} - {}", status, body));
    }

    let body_text = response.text().context("Failed to read response body")?;
    
    let profiles: Vec<SslProfile> = serde_json::from_str(&body_text)
        .context(format!("Failed to parse SSL profiles response. Body: {}", body_text))?;
    
    Ok(profiles)
}

fn strip_csr(csr: &str) -> String {
    csr.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("")
}

pub fn enroll_and_collect(
    config: &SectigoConfig, 
    csr_file: &str, 
    output_cert: &str, 
    description: Option<String>,
    product_code: Option<String>,
    debug: bool
) -> Result<String> {
    let csr_content = fs::read_to_string(csr_file).context("Failed to read CSR file")?;
    let stripped_csr = strip_csr(&csr_content);
    
    // Get Bearer Token
    println!("Authenticating with Sectigo SCM (Admin API v3)...");
    let token = get_scm_token(config, debug)?;

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let cert_type = product_code.unwrap_or_else(|| config.product_code.clone());
    let org_id = config.org_id.clone();

    let payload = EnrollRequest {
        cert_type,
        csr: stripped_csr,
        org_id,
        term: config.term,
    };

    if debug {
        println!("DEBUG: Sectigo Enrollment Request:");
        println!("  URL: {}/api/ssl/v1/enroll", config.api_base);
        println!("  Payload: {}", serde_json::to_string_pretty(&payload).unwrap_or_default());
    }
    
    let response = client.post(&format!("{}/api/ssl/v1/enroll", config.api_base))
        .header("Content-Type", "application/json")
        .bearer_auth(&token)
        .json(&payload)
        .send()
        .context("Failed to send enrollment request")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_else(|_| "Could not read body".to_string());
        println!("  Enrollment Error Status: {}", status);
        println!("  Enrollment Error Body: {}", body);
        return Err(anyhow!("Enrollment failed: {} - {}", status, body));
    }

    let enroll_res: EnrollResponse = response.json()?;
    let ssl_id = enroll_res.ssl_id.context("No sslId returned from enrollment")?;

    println!("Enrollment successful. SSL ID: {}", ssl_id);

    if let Some(desc) = description {
        if !desc.is_empty() {
            println!("Attaching description to certificate...");
            let update_payload = UpdateSslRequest { 
                ssl_id, 
                comments: desc 
            };
            let response = client.put(&format!("{}/api/ssl/v1", config.api_base))
                .header("Content-Type", "application/json")
                .bearer_auth(&token)
                .json(&update_payload)
                .send()
                .context("Failed to attach description")?;
            
            if !response.status().is_success() {
                 println!("  Warning: Failed to attach description: {}", response.status());
            } else {
                 println!("  Description attached successfully.");
            }
        }
    }
    println!("Waiting 20 seconds for certificate to be processed...");
    std::thread::sleep(std::time::Duration::from_secs(20));

    println!("Downloading certificate (PEM format)...");
    let response = client.get(&format!("{}/api/ssl/v1/collect/{}?format=x509", config.api_base, ssl_id))
        .bearer_auth(&token)
        .send()?
        .error_for_status()?;

    let cert_content = response.text()?;
    fs::write(output_cert, &cert_content)?;

    Ok(cert_content)
}

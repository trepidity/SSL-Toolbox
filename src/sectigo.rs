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
    cert_type: i32,
    csr: String,
    #[serde(rename = "orgId")]
    org_id: i32,
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

fn get_scm_token(config: &SectigoConfig) -> Result<String> {
    let client = reqwest::blocking::Client::new();
    
    println!("  URL: {}", config.scm_token_url);
    println!("  Client ID length: {}", config.scm_client_id.len());
    
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

fn strip_csr(csr: &str) -> String {
    csr.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("")
}

pub fn enroll_and_collect(config: &SectigoConfig, csr_file: &str, output_cert: &str, description: Option<String>) -> Result<()> {
    let csr_content = fs::read_to_string(csr_file).context("Failed to read CSR file")?;
    let stripped_csr = strip_csr(&csr_content);
    
    // Get Bearer Token
    println!("Authenticating with Sectigo SCM (Admin API v3)...");
    let token = get_scm_token(config)?;

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let cert_type = config.product_code.parse::<i32>().context("Invalid product_code (cert_type)")?;
    let org_id = config.org_id.parse::<i32>().context("Invalid org_id")?;

    let payload = EnrollRequest {
        cert_type,
        csr: stripped_csr,
        org_id,
        term: config.term,
    };

    println!("DEBUG: Sectigo Enrollment Request:");
    println!("  URL: {}/api/ssl/v1/enroll", config.api_base);
    println!("  Payload: {}", serde_json::to_string_pretty(&payload).unwrap_or_default());
    
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
    fs::write(output_cert, cert_content)?;

    Ok(())
}

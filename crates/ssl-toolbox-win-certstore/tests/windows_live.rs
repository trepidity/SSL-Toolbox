#![cfg(windows)]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use ssl_toolbox_win_certstore::{
    ExportFormat, ExportOptions, ImportOptions, StoreLocation, delete_certificate,
    export_certificate, get_certificate, get_private_key_info, import_file, list_certificates,
};

#[test]
fn current_user_certificate_lifecycle() -> Result<()> {
    if env::var("SSL_TOOLBOX_ENABLE_WINDOWS_LIVE_TESTS")
        .ok()
        .as_deref()
        != Some("1")
    {
        eprintln!("Skipping live Windows certificate-store test.");
        return Ok(());
    }

    let dns_name = format!("ssl-toolbox-live-{}", unique_suffix());
    let password = "ssl-toolbox-test-password!";
    let mut cleanup = Cleanup::default();

    let thumbprint = create_self_signed_cert(&dns_name)?;
    cleanup.thumbprint = Some(thumbprint.clone());

    let listed = list_certificates(StoreLocation::CurrentUser, "MY")?;
    assert!(listed.iter().any(|cert| cert.thumbprint == thumbprint));

    let details = get_certificate(StoreLocation::CurrentUser, "MY", &thumbprint)?;
    assert!(
        details.entry.subject.contains(&dns_name),
        "expected subject to include {dns_name}, got {}",
        details.entry.subject
    );

    let key_info = get_private_key_info(StoreLocation::CurrentUser, "MY", &thumbprint)?;
    assert!(
        !key_info.provider_kind.is_empty(),
        "private-key inspection should return provider metadata"
    );

    let pfx_path = temp_path("pfx");
    cleanup.paths.push(pfx_path.clone());
    export_certificate(&ExportOptions {
        location: StoreLocation::CurrentUser,
        store: "MY".to_string(),
        thumbprint: thumbprint.clone(),
        output_path: pfx_path.to_string_lossy().into_owned(),
        format: ExportFormat::Pfx,
        password: Some(password.to_string()),
    })?;
    assert!(pfx_path.exists(), "expected PFX export to exist");

    delete_certificate(StoreLocation::CurrentUser, "MY", &thumbprint)?;
    cleanup.thumbprint = None;

    let import_result = import_file(&ImportOptions {
        location: StoreLocation::CurrentUser,
        store: "MY".to_string(),
        file_path: pfx_path.to_string_lossy().into_owned(),
        password: Some(password.to_string()),
        exportable: true,
    })?;
    assert!(
        import_result
            .thumbprints
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(&thumbprint)),
        "expected imported thumbprints to include original thumbprint"
    );

    cleanup.thumbprint = Some(thumbprint.clone());

    let pem_path = temp_path("pem");
    cleanup.paths.push(pem_path.clone());
    export_certificate(&ExportOptions {
        location: StoreLocation::CurrentUser,
        store: "MY".to_string(),
        thumbprint: thumbprint.clone(),
        output_path: pem_path.to_string_lossy().into_owned(),
        format: ExportFormat::Pem,
        password: None,
    })?;
    let pem = fs::read_to_string(&pem_path)?;
    assert!(pem.contains("BEGIN CERTIFICATE"));

    Ok(())
}

#[derive(Default)]
struct Cleanup {
    thumbprint: Option<String>,
    paths: Vec<PathBuf>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(thumbprint) = &self.thumbprint {
            let _ = delete_certificate(StoreLocation::CurrentUser, "MY", thumbprint);
        }
        for path in &self.paths {
            let _ = fs::remove_file(path);
        }
    }
}

fn create_self_signed_cert(dns_name: &str) -> Result<String> {
    let script = format!(
        "$cert = New-SelfSignedCertificate -DnsName '{}' -CertStoreLocation 'Cert:\\CurrentUser\\My' -KeyExportPolicy Exportable -NotAfter (Get-Date).AddDays(7); \
         [pscustomobject]@{{ Thumbprint = $cert.Thumbprint }} | ConvertTo-Json -Compress",
        ps_quote(dns_name)
    );
    let output = run_powershell(&script)?;
    let thumbprint = parse_thumbprint(&output)?;
    if thumbprint.is_empty() {
        return Err(anyhow!("PowerShell returned an empty thumbprint"));
    }
    Ok(thumbprint)
}

fn run_powershell(script: &str) -> Result<String> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
        .context("failed to start PowerShell")?;
    if !output.status.success() {
        return Err(anyhow!(
            "PowerShell command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn parse_thumbprint(json: &str) -> Result<String> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    Ok(value
        .get("Thumbprint")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .trim()
        .to_string())
}

fn temp_path(ext: &str) -> PathBuf {
    env::temp_dir().join(format!("ssl-toolbox-live-{}.{}", unique_suffix(), ext))
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    format!("{}-{}", std::process::id(), nanos)
}

fn ps_quote(value: &str) -> String {
    value.replace('\'', "''")
}

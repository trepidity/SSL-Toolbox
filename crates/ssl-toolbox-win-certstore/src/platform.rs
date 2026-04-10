use anyhow::{Result, anyhow};

use crate::{
    CertDetails, CertEntry, ExportOptions, ImportOptions, ImportResult, PhysicalStoreInfo,
    PrivateKeyInfo, StoreInfo, StoreLocationContext, StorePath,
};

#[cfg(not(windows))]
pub(crate) fn list_stores(_location: &StoreLocationContext) -> Result<Vec<StoreInfo>> {
    Err(unsupported())
}

#[cfg(not(windows))]
pub(crate) fn list_physical_stores(
    _location: &StoreLocationContext,
    _store: &str,
) -> Result<Vec<PhysicalStoreInfo>> {
    Err(unsupported())
}

#[cfg(not(windows))]
pub(crate) fn list_certificates(_path: &StorePath) -> Result<Vec<CertEntry>> {
    Err(unsupported())
}

#[cfg(not(windows))]
pub(crate) fn get_certificate(_path: &StorePath, _thumbprint: &str) -> Result<CertDetails> {
    Err(unsupported())
}

#[cfg(not(windows))]
pub(crate) fn get_certificate_by_path(_path: &str) -> Result<CertDetails> {
    Err(unsupported())
}

#[cfg(not(windows))]
pub(crate) fn get_private_key_info(_path: &StorePath, _thumbprint: &str) -> Result<PrivateKeyInfo> {
    Err(unsupported())
}

#[cfg(not(windows))]
pub(crate) fn get_private_key_info_by_path(_path: &str) -> Result<PrivateKeyInfo> {
    Err(unsupported())
}

#[cfg(not(windows))]
pub(crate) fn import_file(_options: &ImportOptions) -> Result<ImportResult> {
    Err(unsupported())
}

#[cfg(not(windows))]
pub(crate) fn export_certificate(_options: &ExportOptions) -> Result<()> {
    Err(unsupported())
}

#[cfg(not(windows))]
pub(crate) fn export_certificate_by_path(
    _path: &str,
    _output_path: &str,
    _format: crate::ExportFormat,
    _password: Option<String>,
) -> Result<()> {
    Err(unsupported())
}

#[cfg(not(windows))]
pub(crate) fn delete_certificate(_path: &StorePath, _thumbprint: &str) -> Result<()> {
    Err(unsupported())
}

#[cfg(not(windows))]
pub(crate) fn delete_certificate_by_path(_path: &str) -> Result<()> {
    Err(unsupported())
}

#[cfg(not(windows))]
pub(crate) fn is_elevated() -> Result<bool> {
    Err(unsupported())
}

#[cfg(not(windows))]
fn unsupported() -> anyhow::Error {
    anyhow!("Windows certificate store management is only supported on Windows.")
}

#[cfg(windows)]
mod windows_impl {
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use anyhow::{Context, Result, anyhow, bail};
    use openssl::x509::X509;
    use serde::Deserialize;
    use serde_json::Value;

    use crate::{
        CertDetails, CertEntry, ExportFormat, ExportOptions, ImportOptions, ImportResult,
        PhysicalStoreInfo, PrivateKeyInfo, StoreInfo, StoreLocation, StoreLocationContext,
        StorePath,
    };

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug, Deserialize)]
    struct RawStoreInfo {
        name: Option<String>,
        path: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct RawPhysicalStoreInfo {
        name: Option<String>,
        path: Option<String>,
        is_logical_view: Option<bool>,
    }

    #[derive(Debug, Deserialize)]
    struct RawCertEntry {
        #[serde(rename = "Path")]
        path: Option<String>,
        #[serde(rename = "Thumbprint")]
        thumbprint: Option<String>,
        #[serde(rename = "Subject")]
        subject: Option<String>,
        #[serde(rename = "Issuer")]
        issuer: Option<String>,
        #[serde(rename = "NotBefore")]
        not_before: Option<String>,
        #[serde(rename = "NotAfter")]
        not_after: Option<String>,
        #[serde(rename = "HasPrivateKey")]
        has_private_key: Option<bool>,
        #[serde(rename = "FriendlyName")]
        friendly_name: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct RawCertDetails {
        #[serde(rename = "Path")]
        path: Option<String>,
        #[serde(rename = "Thumbprint")]
        thumbprint: Option<String>,
        #[serde(rename = "Subject")]
        subject: Option<String>,
        #[serde(rename = "Issuer")]
        issuer: Option<String>,
        #[serde(rename = "NotBefore")]
        not_before: Option<String>,
        #[serde(rename = "NotAfter")]
        not_after: Option<String>,
        #[serde(rename = "HasPrivateKey")]
        has_private_key: Option<bool>,
        #[serde(rename = "FriendlyName")]
        friendly_name: Option<String>,
        #[serde(rename = "SerialNumber")]
        serial_number: Option<String>,
        #[serde(rename = "Version")]
        version: Option<Value>,
        #[serde(rename = "SignatureAlgorithm")]
        signature_algorithm: Option<String>,
        #[serde(rename = "DnsNames")]
        dns_names: Option<Vec<String>>,
    }

    #[derive(Debug, Deserialize)]
    struct RawPrivateKeyInfo {
        #[serde(rename = "ProviderKind")]
        provider_kind: Option<String>,
        #[serde(rename = "ProviderName")]
        provider_name: Option<String>,
        #[serde(rename = "ContainerName")]
        container_name: Option<String>,
        #[serde(rename = "KeySpec")]
        key_spec: Option<String>,
        #[serde(rename = "Exportable")]
        exportable: Option<bool>,
        #[serde(rename = "UserProtected")]
        user_protected: Option<bool>,
        #[serde(rename = "Accessible")]
        accessible: Option<bool>,
        #[serde(rename = "Message")]
        message: Option<String>,
    }

    pub(crate) fn list_stores(location: &StoreLocationContext) -> Result<Vec<StoreInfo>> {
        let location_root = location.provider_root()?;
        let script = format!(
            "$ProgressPreference='SilentlyContinue'; \
             Get-ChildItem -Path '{}' | \
             Sort-Object PSChildName | \
             Select-Object @{{Name='name';Expression={{$_.PSChildName}}}}, @{{Name='path';Expression={{$_.PSPath}}}} | \
             ConvertTo-Json -Depth 4 -Compress",
            ps_quote(&location_root)
        );

        let stores = parse_many::<RawStoreInfo>(&run_powershell(&script)?)?;
        Ok(stores
            .into_iter()
            .filter_map(|store| {
                let name = store.name?.trim().to_string();
                if name.is_empty() {
                    return None;
                }
                Some(StoreInfo {
                    path: store.path.unwrap_or_default(),
                    name,
                    location: Some(location.clone()),
                })
            })
            .collect())
    }

    pub(crate) fn list_physical_stores(
        location: &StoreLocationContext,
        store: &str,
    ) -> Result<Vec<PhysicalStoreInfo>> {
        let store_path = StorePath::new(location.clone(), store, None);
        let provider_path = cert_store_path(&store_path)?;
        let script = format!(
            "$ProgressPreference='SilentlyContinue'; \
             $store = Get-Item -Path '{}'; \
             $physical = @(); \
             $logical = [pscustomobject]@{{ name = '.Logical'; path = '{}'; is_logical_view = $true }}; \
             $physical += $logical; \
             if ($store.PSObject.Properties.Name -contains 'StoreNames') {{ \
                 foreach ($name in $store.StoreNames) {{ \
                     if ($name -and $name -ne '.Logical') {{ \
                         $physical += [pscustomobject]@{{ name = $name; path = '{}\\' + $name; is_logical_view = $false }}; \
                     }} \
                 }} \
             }}; \
             $physical | Sort-Object name -Unique | ConvertTo-Json -Depth 4 -Compress",
            ps_quote(&provider_path),
            ps_quote(&provider_path),
            ps_quote(&provider_path)
        );

        let entries = parse_many::<RawPhysicalStoreInfo>(&run_powershell(&script)?)?;
        Ok(entries
            .into_iter()
            .filter_map(|entry| {
                let name = normalize_opt(entry.name)?;
                Some(PhysicalStoreInfo {
                    path: entry.path.unwrap_or_default(),
                    name,
                    is_logical_view: entry.is_logical_view.unwrap_or(false),
                })
            })
            .collect())
    }

    pub(crate) fn list_certificates(path: &StorePath) -> Result<Vec<CertEntry>> {
        let provider_path = cert_store_path(path)?;
        let script = format!(
            "$ProgressPreference='SilentlyContinue'; \
             if (-not (Test-Path '{}')) {{ throw 'Store not found: {}'; }}; \
             Get-ChildItem -Path '{}' | \
             Sort-Object Subject | \
             Select-Object @{{Name='Path';Expression={{$_.PSPath}}}}, Thumbprint, Subject, Issuer, \
                 @{{Name='NotBefore';Expression={{$_.NotBefore.ToString('o')}}}}, \
                 @{{Name='NotAfter';Expression={{$_.NotAfter.ToString('o')}}}}, \
                 HasPrivateKey, FriendlyName | \
             ConvertTo-Json -Depth 4 -Compress",
            ps_quote(&provider_path),
            ps_quote(&provider_path),
            ps_quote(&provider_path)
        );

        let entries = parse_many::<RawCertEntry>(&run_powershell(&script)?)?;
        Ok(entries
            .into_iter()
            .map(|raw| map_entry(raw, path))
            .collect())
    }

    pub(crate) fn get_certificate(path: &StorePath, thumbprint: &str) -> Result<CertDetails> {
        let item_path = cert_item_path(path, thumbprint)?;
        get_certificate_by_path(&item_path)
    }

    pub(crate) fn get_certificate_by_path(path: &str) -> Result<CertDetails> {
        let script = format!(
            "$ProgressPreference='SilentlyContinue'; \
             $cert = Get-Item -Path '{}'; \
             $dns = @(); \
             if ($cert.DnsNameList) {{ $dns = @($cert.DnsNameList | ForEach-Object {{ $_.Unicode }}) }}; \
             [pscustomobject]@{{ \
                 Path = $cert.PSPath; \
                 Thumbprint = $cert.Thumbprint; \
                 Subject = $cert.Subject; \
                 Issuer = $cert.Issuer; \
                 NotBefore = $cert.NotBefore.ToString('o'); \
                 NotAfter = $cert.NotAfter.ToString('o'); \
                 HasPrivateKey = $cert.HasPrivateKey; \
                 FriendlyName = $cert.FriendlyName; \
                 SerialNumber = $cert.SerialNumber; \
                 Version = $cert.Version; \
                 SignatureAlgorithm = if ($cert.SignatureAlgorithm) {{ $cert.SignatureAlgorithm.FriendlyName }} else {{ $null }}; \
                 DnsNames = $dns \
             }} | ConvertTo-Json -Depth 6 -Compress",
            ps_quote(path)
        );

        let raw = parse_one::<RawCertDetails>(&run_powershell(&script)?)?;
        Ok(CertDetails {
            entry: CertEntry {
                path: raw.path.unwrap_or_else(|| path.to_string()),
                store_path: None,
                identity_hint: None,
                thumbprint: raw.thumbprint.unwrap_or_default(),
                subject: raw.subject.unwrap_or_default(),
                issuer: raw.issuer.unwrap_or_default(),
                not_before: raw.not_before.unwrap_or_default(),
                not_after: raw.not_after.unwrap_or_default(),
                has_private_key: raw.has_private_key.unwrap_or(false),
                friendly_name: normalize_opt(raw.friendly_name),
            },
            serial_number: normalize_opt(raw.serial_number),
            version: raw.version.map(|value| match value {
                Value::String(s) => s,
                other => other.to_string(),
            }),
            signature_algorithm: normalize_opt(raw.signature_algorithm),
            dns_names: raw.dns_names.unwrap_or_default(),
        })
    }

    pub(crate) fn get_private_key_info(
        path: &StorePath,
        thumbprint: &str,
    ) -> Result<PrivateKeyInfo> {
        let item_path = cert_item_path(path, thumbprint)?;
        get_private_key_info_by_path(&item_path)
    }

    pub(crate) fn get_private_key_info_by_path(path: &str) -> Result<PrivateKeyInfo> {
        let script = format!(
            "$ProgressPreference='SilentlyContinue'; \
             $cert = Get-Item -Path '{}'; \
             if (-not $cert.HasPrivateKey) {{ \
                 [pscustomobject]@{{ \
                     ProviderKind = 'None'; \
                     ProviderName = $null; \
                     ContainerName = $null; \
                     KeySpec = $null; \
                     Exportable = $false; \
                     UserProtected = $false; \
                     Accessible = $false; \
                     Message = 'Certificate does not have an associated private key.' \
                 }} | ConvertTo-Json -Depth 6 -Compress; \
                 return; \
             }}; \
             Add-Type -AssemblyName System.Security; \
             $info = [ordered]@{{ \
                 ProviderKind = 'Associated'; \
                 ProviderName = $null; \
                 ContainerName = $null; \
                 KeySpec = $null; \
                 Exportable = $null; \
                 UserProtected = $null; \
                 Accessible = $true; \
                 Message = $null \
             }}; \
             try {{ \
                 $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert); \
                 if ($rsa -is [System.Security.Cryptography.RSACng]) {{ \
                     $info.ProviderKind = 'CNG'; \
                     $info.ProviderName = $rsa.Key.Provider.Provider; \
                     $info.ContainerName = $rsa.Key.KeyName; \
                     $info.KeySpec = 'NCRYPT'; \
                     $info.Exportable = [bool](($rsa.Key.ExportPolicy -band [System.Security.Cryptography.CngExportPolicies]::AllowExport) -ne 0); \
                     $info.UserProtected = [bool](($rsa.Key.ExportPolicy -band [System.Security.Cryptography.CngExportPolicies]::AllowUserProtectedExport) -ne 0); \
                 }} elseif ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) {{ \
                     $info.ProviderKind = 'CryptoAPI'; \
                     $info.ProviderName = $rsa.CspKeyContainerInfo.ProviderName; \
                     $info.ContainerName = $rsa.CspKeyContainerInfo.KeyContainerName; \
                     $info.KeySpec = $rsa.CspKeyContainerInfo.KeyNumber.ToString(); \
                     $info.Exportable = $rsa.CspKeyContainerInfo.Exportable; \
                     $info.UserProtected = $rsa.CspKeyContainerInfo.Protected; \
                 }} \
             }} catch {{}}; \
             if (-not $info.ProviderName) {{ \
                 try {{ \
                     $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert); \
                     if ($ecdsa -is [System.Security.Cryptography.ECDsaCng]) {{ \
                         $info.ProviderKind = 'CNG'; \
                         $info.ProviderName = $ecdsa.Key.Provider.Provider; \
                         $info.ContainerName = $ecdsa.Key.KeyName; \
                         $info.KeySpec = 'NCRYPT'; \
                         $info.Exportable = [bool](($ecdsa.Key.ExportPolicy -band [System.Security.Cryptography.CngExportPolicies]::AllowExport) -ne 0); \
                         $info.UserProtected = [bool](($ecdsa.Key.ExportPolicy -band [System.Security.Cryptography.CngExportPolicies]::AllowUserProtectedExport) -ne 0); \
                     }} \
                 }} catch {{}} \
             }}; \
             if (-not $info.ProviderName) {{ \
                 try {{ \
                     $cert.PrivateKey | Out-Null; \
                 }} catch {{ \
                     $info.Accessible = $false; \
                     $info.Message = $_.Exception.Message; \
                 }} \
             }}; \
             [pscustomobject]$info | ConvertTo-Json -Depth 6 -Compress",
            ps_quote(path)
        );

        let raw = parse_one::<RawPrivateKeyInfo>(&run_powershell(&script)?)?;
        Ok(PrivateKeyInfo {
            provider_kind: raw.provider_kind.unwrap_or_else(|| "Unknown".to_string()),
            provider_name: normalize_opt(raw.provider_name),
            container_name: normalize_opt(raw.container_name),
            key_spec: normalize_opt(raw.key_spec),
            exportable: raw.exportable,
            user_protected: raw.user_protected,
            accessible: raw.accessible.unwrap_or(false),
            message: normalize_opt(raw.message),
        })
    }

    pub(crate) fn import_file(options: &ImportOptions) -> Result<ImportResult> {
        let data = fs::read(&options.file_path)
            .with_context(|| format!("Failed to read {}", options.file_path))?;
        let detected = ssl_toolbox_core::convert::detect_format(&data);
        let store_path = cert_store_path(&StorePath::new(
            StoreLocationContext::new(options.location, None)?,
            &options.store,
            None,
        ))?;

        let imported = match detected {
            ssl_toolbox_core::CertFormat::Pkcs12 => import_pfx(options, &store_path)?,
            ssl_toolbox_core::CertFormat::Pem => import_pem_bundle(&store_path, &data)?,
            ssl_toolbox_core::CertFormat::Der
            | ssl_toolbox_core::CertFormat::Pkcs7
            | ssl_toolbox_core::CertFormat::Base64 => {
                let normalized = normalize_certificate_file(&options.file_path, &data, detected)?;
                import_certificate_file(&store_path, &normalized)?
            }
            ssl_toolbox_core::CertFormat::Unknown => {
                bail!(
                    "Unsupported certificate format for import: {}",
                    options.file_path
                )
            }
        };

        Ok(imported)
    }

    pub(crate) fn export_certificate(options: &ExportOptions) -> Result<()> {
        let item_path = cert_item_path(
            &StorePath::new(
                StoreLocationContext::new(options.location, None)?,
                &options.store,
                None,
            ),
            &options.thumbprint,
        )?;
        export_certificate_by_path(
            &item_path,
            &options.output_path,
            options.format,
            options.password.clone(),
        )
    }

    pub(crate) fn export_certificate_by_path(
        path: &str,
        output_path: &str,
        format: ExportFormat,
        password: Option<String>,
    ) -> Result<()> {
        match format {
            ExportFormat::Der => export_der(path, output_path),
            ExportFormat::Pem => export_pem(path, output_path),
            ExportFormat::Pfx => export_pfx(path, output_path, password),
        }
    }

    pub(crate) fn delete_certificate(path: &StorePath, thumbprint: &str) -> Result<()> {
        let item_path = cert_item_path(path, thumbprint)?;
        delete_certificate_by_path(&item_path)
    }

    pub(crate) fn delete_certificate_by_path(path: &str) -> Result<()> {
        let script = format!(
            "$ProgressPreference='SilentlyContinue'; \
             Remove-Item -Path '{}' -Force",
            ps_quote(path)
        );
        run_powershell(&script)?;
        Ok(())
    }

    pub(crate) fn is_elevated() -> Result<bool> {
        let script = "$ProgressPreference='SilentlyContinue'; \
            $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); \
            [pscustomobject]@{ Elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } | \
            ConvertTo-Json -Compress";
        #[derive(Debug, Deserialize)]
        struct ElevationProbe {
            #[serde(rename = "Elevated")]
            elevated: Option<bool>,
        }

        let probe = parse_one::<ElevationProbe>(&run_powershell(script)?)?;
        Ok(probe.elevated.unwrap_or(false))
    }

    fn import_pfx(options: &ImportOptions, store_path: &str) -> Result<ImportResult> {
        let password_expr = match &options.password {
            Some(password) => format!(
                "(ConvertTo-SecureString '{}' -AsPlainText -Force)",
                ps_quote(password)
            ),
            None => "(ConvertTo-SecureString '' -AsPlainText -Force)".to_string(),
        };
        let exportable_flag = if options.exportable {
            "-Exportable"
        } else {
            ""
        };
        let script = format!(
            "$ProgressPreference='SilentlyContinue'; \
             Import-PfxCertificate -FilePath '{}' -CertStoreLocation '{}' -Password {} {} | \
             Select-Object Thumbprint | ConvertTo-Json -Depth 4 -Compress",
            ps_quote(&options.file_path),
            ps_quote(store_path),
            password_expr,
            exportable_flag
        );
        let thumbprints = parse_many::<ThumbprintOnly>(&run_powershell(&script)?)?
            .into_iter()
            .filter_map(|item| normalize_opt(item.thumbprint))
            .collect::<Vec<_>>();
        Ok(ImportResult {
            imported: thumbprints.len(),
            thumbprints,
        })
    }

    fn import_certificate_file(store_path: &str, file_path: &str) -> Result<ImportResult> {
        let script = format!(
            "$ProgressPreference='SilentlyContinue'; \
             Import-Certificate -FilePath '{}' -CertStoreLocation '{}' | \
             Select-Object Thumbprint | ConvertTo-Json -Depth 4 -Compress",
            ps_quote(file_path),
            ps_quote(store_path)
        );
        let thumbprints = parse_many::<ThumbprintOnly>(&run_powershell(&script)?)?
            .into_iter()
            .filter_map(|item| normalize_opt(item.thumbprint))
            .collect::<Vec<_>>();
        Ok(ImportResult {
            imported: thumbprints.len(),
            thumbprints,
        })
    }

    fn import_pem_bundle(store_path: &str, data: &[u8]) -> Result<ImportResult> {
        let certs = X509::stack_from_pem(data).context("Failed to parse PEM certificate bundle")?;
        let mut thumbprints = Vec::new();
        let mut temp_paths = Vec::new();

        for cert in certs {
            let temp = temp_path("ssl-toolbox-import", "cer");
            fs::write(
                &temp,
                cert.to_der().context("Failed to convert PEM to DER")?,
            )?;
            temp_paths.push(temp.clone());
            let result = import_certificate_file(store_path, temp.to_string_lossy().as_ref())?;
            thumbprints.extend(result.thumbprints);
        }

        for temp in temp_paths {
            let _ = fs::remove_file(temp);
        }

        Ok(ImportResult {
            imported: thumbprints.len(),
            thumbprints,
        })
    }

    fn export_der(item_path: &str, output_path: &str) -> Result<()> {
        let script = format!(
            "$ProgressPreference='SilentlyContinue'; \
             Export-Certificate -Cert (Get-Item -Path '{}') -FilePath '{}' -Type CERT -Force | Out-Null",
            ps_quote(item_path),
            ps_quote(output_path)
        );
        run_powershell(&script)?;
        Ok(())
    }

    fn export_pem(item_path: &str, output_path: &str) -> Result<()> {
        let temp_der = temp_path("ssl-toolbox-export", "cer");
        export_der(item_path, temp_der.to_string_lossy().as_ref())?;
        ssl_toolbox_core::convert::der_to_pem(temp_der.to_string_lossy().as_ref(), output_path)?;
        let _ = fs::remove_file(temp_der);
        Ok(())
    }

    fn export_pfx(item_path: &str, output_path: &str, password: Option<String>) -> Result<()> {
        let password = password
            .as_ref()
            .ok_or_else(|| anyhow!("PFX export requires --pfx-password"))?;
        let script = format!(
            "$ProgressPreference='SilentlyContinue'; \
             Export-PfxCertificate -Cert (Get-Item -Path '{}') -FilePath '{}' -Password (ConvertTo-SecureString '{}' -AsPlainText -Force) -Force | Out-Null",
            ps_quote(item_path),
            ps_quote(output_path),
            ps_quote(password)
        );
        run_powershell(&script)?;
        Ok(())
    }

    fn normalize_certificate_file(
        original_path: &str,
        data: &[u8],
        format: ssl_toolbox_core::CertFormat,
    ) -> Result<String> {
        match format {
            ssl_toolbox_core::CertFormat::Der | ssl_toolbox_core::CertFormat::Pkcs7 => {
                Ok(original_path.to_string())
            }
            ssl_toolbox_core::CertFormat::Pem => {
                let temp = temp_path("ssl-toolbox-import", "cer");
                let cert = X509::from_pem(data).context("Failed to parse PEM certificate")?;
                fs::write(
                    &temp,
                    cert.to_der().context("Failed to convert PEM to DER")?,
                )?;
                Ok(temp.to_string_lossy().into_owned())
            }
            ssl_toolbox_core::CertFormat::Base64 => {
                let text = std::str::from_utf8(data).context("Base64 input is not valid UTF-8")?;
                let decoded = decode_base64_stripped(text)?;
                let temp = temp_path("ssl-toolbox-import", "cer");
                fs::write(&temp, decoded)?;
                Ok(temp.to_string_lossy().into_owned())
            }
            ssl_toolbox_core::CertFormat::Pkcs12 | ssl_toolbox_core::CertFormat::Unknown => {
                Ok(original_path.to_string())
            }
        }
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
            .context("Failed to start PowerShell")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let detail = if !stderr.is_empty() { stderr } else { stdout };
            bail!("PowerShell command failed: {}", detail);
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn parse_many<T>(json: &str) -> Result<Vec<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        if json.trim().is_empty() {
            return Ok(Vec::new());
        }
        let value: Value = serde_json::from_str(json).context("Failed to parse PowerShell JSON")?;
        match value {
            Value::Array(items) => items
                .into_iter()
                .map(|item| serde_json::from_value(item).context("Failed to decode JSON item"))
                .collect(),
            Value::Null => Ok(Vec::new()),
            other => Ok(vec![
                serde_json::from_value(other).context("Failed to decode JSON item")?,
            ]),
        }
    }

    fn parse_one<T>(json: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut values = parse_many::<T>(json)?;
        values
            .drain(..)
            .next()
            .ok_or_else(|| anyhow!("PowerShell returned no data"))
    }

    fn cert_store_path(path: &StorePath) -> Result<String> {
        let root = path.location.provider_root()?;
        if let Some(physical) = &path.physical_store {
            Ok(format!(r"{}\{}\{}", root, path.store_name, physical))
        } else {
            Ok(format!(r"{}\{}", root, path.store_name))
        }
    }

    fn cert_item_path(path: &StorePath, thumbprint: &str) -> Result<String> {
        Ok(format!(r"{}\{}", cert_store_path(path)?, thumbprint))
    }

    fn ps_quote(input: &str) -> String {
        input.replace('\'', "''")
    }

    fn normalize_opt(input: Option<String>) -> Option<String> {
        input.and_then(|value| {
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
    }

    fn map_entry(raw: RawCertEntry, path: &StorePath) -> CertEntry {
        let thumbprint = raw.thumbprint.unwrap_or_default();
        CertEntry {
            path: raw.path.unwrap_or_default(),
            store_path: Some(path.clone()),
            identity_hint: Some(format!(
                "{}|{}|{}|{}",
                path.location,
                path.store_name,
                path.physical_store.as_deref().unwrap_or(".Logical"),
                thumbprint
            )),
            thumbprint,
            subject: raw.subject.unwrap_or_default(),
            issuer: raw.issuer.unwrap_or_default(),
            not_before: raw.not_before.unwrap_or_default(),
            not_after: raw.not_after.unwrap_or_default(),
            has_private_key: raw.has_private_key.unwrap_or(false),
            friendly_name: normalize_opt(raw.friendly_name),
        }
    }

    fn temp_path(prefix: &str, ext: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("{}-{}-{}.{}", prefix, nanos, counter, ext))
    }

    fn decode_base64_stripped(input: &str) -> Result<Vec<u8>> {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let clean: Vec<u8> = input
            .bytes()
            .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
            .collect();
        let mut output = Vec::new();

        for chunk in clean.chunks(4) {
            let mut buf = [0u8; 4];
            let len = chunk.len();
            for (i, byte) in chunk.iter().enumerate() {
                buf[i] = TABLE
                    .iter()
                    .position(|candidate| candidate == byte)
                    .ok_or_else(|| anyhow!("Base64 input contains an invalid character"))?
                    as u8;
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

        Ok(output)
    }

    #[derive(Debug, Deserialize)]
    struct ThumbprintOnly {
        #[serde(rename = "Thumbprint")]
        thumbprint: Option<String>,
    }
}

#[cfg(windows)]
pub(crate) use windows_impl::*;

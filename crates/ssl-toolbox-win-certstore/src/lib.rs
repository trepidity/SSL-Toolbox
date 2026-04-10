mod platform;

use std::fmt;
use std::path::Path;

use anyhow::{Result, anyhow};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreLocation {
    CurrentUser,
    LocalMachine,
    CurrentService,
    Service,
    User,
}

impl StoreLocation {
    pub fn parse(input: &str) -> Result<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "current-user" | "currentuser" | "user" => Ok(Self::CurrentUser),
            "local-machine" | "localmachine" | "machine" => Ok(Self::LocalMachine),
            "current-service" | "currentservice" => Ok(Self::CurrentService),
            "service" => Ok(Self::Service),
            "user-store" | "user-context" | "alternate-user" => Ok(Self::User),
            other => Err(anyhow!(
                "Unsupported store location '{}'. Use current-user, local-machine, current-service, service, or user-store.",
                other
            )),
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::CurrentUser, Self::LocalMachine, Self::CurrentService]
    }

    pub fn provider_root(self) -> &'static str {
        match self {
            Self::CurrentUser => "Cert:\\CurrentUser",
            Self::LocalMachine => "Cert:\\LocalMachine",
            Self::CurrentService => "Cert:\\CurrentService",
            Self::Service => "Cert:\\Service",
            Self::User => "Cert:\\User",
        }
    }

    pub fn requires_qualifier(self) -> bool {
        matches!(self, Self::Service | Self::User)
    }
}

impl fmt::Display for StoreLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrentUser => write!(f, "current-user"),
            Self::LocalMachine => write!(f, "local-machine"),
            Self::CurrentService => write!(f, "current-service"),
            Self::Service => write!(f, "service"),
            Self::User => write!(f, "user-store"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreLocationContext {
    pub location: StoreLocation,
    pub qualifier: Option<String>,
}

impl StoreLocationContext {
    pub fn new(location: StoreLocation, qualifier: Option<String>) -> Result<Self> {
        let qualifier = qualifier.and_then(|value| {
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });

        if location.requires_qualifier() && qualifier.is_none() {
            return Err(anyhow!("{} store locations require a qualifier", location));
        }

        Ok(Self {
            location,
            qualifier,
        })
    }

    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if let Some(value) = trimmed.strip_prefix("service:") {
            return Self::new(StoreLocation::Service, Some(value.to_string()));
        }
        if let Some(value) = trimmed.strip_prefix("user:") {
            return Self::new(StoreLocation::User, Some(value.to_string()));
        }
        Self::new(StoreLocation::parse(trimmed)?, None)
    }

    pub fn provider_root(&self) -> Result<String> {
        if self.location.requires_qualifier() {
            let qualifier = self
                .qualifier
                .as_ref()
                .ok_or_else(|| anyhow!("{} store locations require a qualifier", self.location))?;
            Ok(format!(r"{}\{}", self.location.provider_root(), qualifier))
        } else {
            Ok(self.location.provider_root().to_string())
        }
    }
}

impl fmt::Display for StoreLocationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(qualifier) = &self.qualifier {
            write!(f, "{}:{}", self.location, qualifier)
        } else {
            write!(f, "{}", self.location)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreInfo {
    pub name: String,
    pub path: String,
    pub location: Option<StoreLocationContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalStoreInfo {
    pub name: String,
    pub path: String,
    pub is_logical_view: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorePath {
    pub location: StoreLocationContext,
    pub store_name: String,
    pub physical_store: Option<String>,
}

impl StorePath {
    pub fn new(
        location: StoreLocationContext,
        store_name: impl Into<String>,
        physical_store: Option<String>,
    ) -> Self {
        Self {
            location,
            store_name: store_name.into(),
            physical_store: physical_store.and_then(|value| {
                let trimmed = value.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertEntry {
    pub path: String,
    pub store_path: Option<StorePath>,
    pub identity_hint: Option<String>,
    pub thumbprint: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub has_private_key: bool,
    pub friendly_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertDetails {
    pub entry: CertEntry,
    pub serial_number: Option<String>,
    pub version: Option<String>,
    pub signature_algorithm: Option<String>,
    pub dns_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKeyInfo {
    pub provider_kind: String,
    pub provider_name: Option<String>,
    pub container_name: Option<String>,
    pub key_spec: Option<String>,
    pub exportable: Option<bool>,
    pub user_protected: Option<bool>,
    pub accessible: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Der,
    Pem,
    Pfx,
}

impl ExportFormat {
    pub fn parse(input: &str) -> Result<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "der" | "cer" => Ok(Self::Der),
            "pem" => Ok(Self::Pem),
            "pfx" | "pkcs12" | "pkcs-12" => Ok(Self::Pfx),
            other => Err(anyhow!(
                "Unsupported export format '{}'. Use der, pem, or pfx.",
                other
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ImportOptions {
    pub location: StoreLocation,
    pub store: String,
    pub file_path: String,
    pub password: Option<String>,
    pub exportable: bool,
}

#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub location: StoreLocation,
    pub store: String,
    pub thumbprint: String,
    pub output_path: String,
    pub format: ExportFormat,
    pub password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ImportResult {
    pub imported: usize,
    pub thumbprints: Vec<String>,
}

pub fn list_store_locations() -> Vec<StoreLocation> {
    StoreLocation::all().to_vec()
}

pub fn list_store_location_contexts() -> Vec<StoreLocationContext> {
    StoreLocation::all()
        .into_iter()
        .map(|location| StoreLocationContext::new(location, None))
        .collect::<Result<Vec<_>>>()
        .unwrap_or_default()
}

pub fn list_stores(location: StoreLocation) -> Result<Vec<StoreInfo>> {
    platform::list_stores(&StoreLocationContext::new(location, None)?)
}

pub fn list_stores_for_context(location: &StoreLocationContext) -> Result<Vec<StoreInfo>> {
    platform::list_stores(location)
}

pub fn list_physical_stores(
    location: &StoreLocationContext,
    store: &str,
) -> Result<Vec<PhysicalStoreInfo>> {
    platform::list_physical_stores(location, store)
}

pub fn list_certificates(location: StoreLocation, store: &str) -> Result<Vec<CertEntry>> {
    platform::list_certificates(&StorePath::new(
        StoreLocationContext::new(location, None)?,
        store,
        None,
    ))
}

pub fn list_certificates_in_store(path: &StorePath) -> Result<Vec<CertEntry>> {
    platform::list_certificates(path)
}

pub fn get_certificate(
    location: StoreLocation,
    store: &str,
    thumbprint: &str,
) -> Result<CertDetails> {
    platform::get_certificate(
        &StorePath::new(StoreLocationContext::new(location, None)?, store, None),
        thumbprint,
    )
}

pub fn get_certificate_in_store(path: &StorePath, thumbprint: &str) -> Result<CertDetails> {
    platform::get_certificate(path, thumbprint)
}

pub fn get_certificate_by_path(path: &str) -> Result<CertDetails> {
    platform::get_certificate_by_path(path)
}

pub fn get_private_key_info(
    location: StoreLocation,
    store: &str,
    thumbprint: &str,
) -> Result<PrivateKeyInfo> {
    platform::get_private_key_info(
        &StorePath::new(StoreLocationContext::new(location, None)?, store, None),
        thumbprint,
    )
}

pub fn get_private_key_info_in_store(path: &StorePath, thumbprint: &str) -> Result<PrivateKeyInfo> {
    platform::get_private_key_info(path, thumbprint)
}

pub fn get_private_key_info_by_path(path: &str) -> Result<PrivateKeyInfo> {
    platform::get_private_key_info_by_path(path)
}

pub fn import_file(options: &ImportOptions) -> Result<ImportResult> {
    if !Path::new(&options.file_path).exists() {
        return Err(anyhow!("File not found: {}", options.file_path));
    }
    platform::import_file(options)
}

pub fn export_certificate(options: &ExportOptions) -> Result<()> {
    platform::export_certificate(options)
}

pub fn export_certificate_by_path(
    path: &str,
    output_path: &str,
    format: ExportFormat,
    password: Option<String>,
) -> Result<()> {
    platform::export_certificate_by_path(path, output_path, format, password)
}

pub fn delete_certificate(location: StoreLocation, store: &str, thumbprint: &str) -> Result<()> {
    platform::delete_certificate(
        &StorePath::new(StoreLocationContext::new(location, None)?, store, None),
        thumbprint,
    )
}

pub fn delete_certificate_in_store(path: &StorePath, thumbprint: &str) -> Result<()> {
    platform::delete_certificate(path, thumbprint)
}

pub fn delete_certificate_by_path(path: &str) -> Result<()> {
    platform::delete_certificate_by_path(path)
}

pub fn is_elevated() -> Result<bool> {
    platform::is_elevated()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_store_locations() {
        assert_eq!(
            StoreLocation::parse("current-user").unwrap(),
            StoreLocation::CurrentUser
        );
        assert_eq!(
            StoreLocation::parse("local-machine").unwrap(),
            StoreLocation::LocalMachine
        );
        assert_eq!(
            StoreLocation::parse("current-service").unwrap(),
            StoreLocation::CurrentService
        );
    }

    #[test]
    fn rejects_unknown_store_location() {
        assert!(StoreLocation::parse("services").is_err());
    }

    #[test]
    fn parses_export_formats() {
        assert_eq!(ExportFormat::parse("pem").unwrap(), ExportFormat::Pem);
        assert_eq!(ExportFormat::parse("der").unwrap(), ExportFormat::Der);
        assert_eq!(ExportFormat::parse("pfx").unwrap(), ExportFormat::Pfx);
    }

    #[test]
    fn parses_store_location_contexts() {
        let current = StoreLocationContext::parse("current-user").unwrap();
        assert_eq!(current.location, StoreLocation::CurrentUser);
        assert!(current.qualifier.is_none());

        let service = StoreLocationContext::parse("service:Spooler").unwrap();
        assert_eq!(service.location, StoreLocation::Service);
        assert_eq!(service.qualifier.as_deref(), Some("Spooler"));

        let user = StoreLocationContext::parse("user:CORP\\jdoe").unwrap();
        assert_eq!(user.location, StoreLocation::User);
        assert_eq!(user.qualifier.as_deref(), Some("CORP\\jdoe"));
    }

    #[test]
    fn rejects_missing_qualified_contexts() {
        assert!(StoreLocationContext::new(StoreLocation::Service, None).is_err());
        assert!(StoreLocationContext::new(StoreLocation::User, None).is_err());
    }
}

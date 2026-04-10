# Windows Certificate Manager Integration -- Full Implementation Spec

**Date:** 2026-04-10
**Status:** Approved
**Approach:** ratatui TUI for cert manager, cliclack retained for existing features

**Implementation Note (2026-04-10):** the current live implementation in this repo
ships as a Windows CLI plus ratatui browser backed by PowerShell certificate-store
commands. Private-key inspection, resume/elevation plumbing, and Windows live-store
CI tests are now implemented. The codebase also has partial backend/UI support for
physical-store browsing and qualified service/user store contexts, but those flows
still depend on the PowerShell/provider-path model and still need Windows-host
validation. The lower-level Win32 exact-handle model in this spec remains future work.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Crate Architecture](#2-crate-architecture)
3. [Data Models](#3-data-models)
4. [Library Crate Public API](#4-library-crate-public-api)
5. [Windows API Call Map](#5-windows-api-call-map)
6. [Error Handling](#6-error-handling)
7. [Navigation & Screen Architecture](#7-navigation--screen-architecture)
8. [Certificate List & Filtering](#8-certificate-list--filtering)
9. [Certificate Detail View](#9-certificate-detail-view)
10. [Import Operations](#10-import-operations)
11. [Export Operations](#11-export-operations)
12. [Delete Operations](#12-delete-operations)
13. [Authentication & Elevation](#13-authentication--elevation)
14. [Dependencies & Conditional Compilation](#14-dependencies--conditional-compilation)
15. [Event Loop & Screen Trait](#15-event-loop--screen-trait)
16. [TUI Widget Specifications](#16-tui-widget-specifications)
17. [CLI Subcommand Integration](#17-cli-subcommand-integration)
18. [Integration with ssl-toolbox-core](#18-integration-with-ssl-toolbox-core)
19. [Performance & Caching](#19-performance--caching)
20. [Edge Cases](#20-edge-cases)
21. [Testing Strategy](#21-testing-strategy)
22. [Windows Certificate Store Reference](#22-windows-certificate-store-reference)
23. [Key Technology Decisions](#23-key-technology-decisions)

---

## 1. Overview

Add a Windows Certificate Manager feature to SSL-Toolbox that provides full interactive access to the Windows certificate stores. The feature launches as a ratatui-based TUI from the existing cliclack main menu, offering tree-style navigation through store locations, store names, physical stores, and individual certificates. Supports viewing public/private keys, importing and exporting in all standard formats, and authentication/elevation for privileged operations.

The feature also exposes direct CLI subcommands for non-interactive use (scripting, automation).

This is a future-state implementation spec. It intentionally describes planned
crates, modules, and command wiring that do not yet exist in the current repo.
Code snippets in this document show the intended API and control flow; they are
design-level examples and may need final Rust translation during implementation.

---

## 2. Crate Architecture

### 2.1 New crate: `ssl-toolbox-win-certstore`

A Windows-only library crate providing certificate store operations with no UI dependency. Zero knowledge of ratatui, crossterm, or any presentation concern.

```
crates/ssl-toolbox-win-certstore/
  Cargo.toml
  src/
    lib.rs              -- Public API surface, re-exports
    store.rs            -- Store enumeration, open, physical store discovery
    cert.rs             -- Certificate reading, parsing, property extraction
    private_key.rs      -- Private key detection, inspection, export
    import.rs           -- Import operations (PFX, PEM, DER, PKCS7, Base64)
    export.rs           -- Export operations (same formats)
    auth.rs             -- Elevation detection, UAC re-launch, user impersonation
    error.rs            -- WinCertError enum, Windows HRESULT mapping
    types.rs            -- All data structures (StoreLocation, CertEntry, etc.)
    win32.rs            -- Thin unsafe wrappers around windows-sys calls
```

### 2.2 TUI layer in binary crate: `src/win_certmgr/`

Presentation logic using ratatui. Gated behind `#[cfg(target_os = "windows")]`.

```
crates/ssl-toolbox/src/win_certmgr/
  mod.rs              -- Entry point: launch_certmgr(resume_args)
  app.rs              -- AppState, navigation stack, event loop, Action dispatch
  screens/
    mod.rs
    location.rs       -- Store location select (CurrentUser, LocalMachine, Service, User)
    store_list.rs     -- Store name select for chosen location
    store_view.rs     -- Paginated cert list with search/filter/sort
    physical.rs       -- Physical store list and browsing
    cert_detail.rs    -- Full certificate detail view (scrollable)
    key_inspect.rs    -- Private key inspection overlay
  widgets/
    mod.rs
    breadcrumb.rs     -- Breadcrumb bar widget
    cert_table.rs     -- Paginated, sortable, filterable cert table
    search_bar.rs     -- Search/filter input with mode indicator
    status_bar.rs     -- Footer: page info, elevation status, help hints
    dialog.rs         -- Modal dialogs: confirm, auth, import preview, error
    file_input.rs     -- File path input with tab-completion
  actions/
    mod.rs
    import.rs         -- Import flow state machine
    export.rs         -- Export flow state machine
    delete.rs         -- Delete flow with thumbprint confirmation
  theme.rs            -- Color palette, border styles, consistent styling
```

### 2.3 Separation of concerns

| Layer | Crate | Responsibility |
|-------|-------|----------------|
| Data operations | `ssl-toolbox-win-certstore` | Open stores, enumerate certs, parse properties, import/export, auth. Returns `Result<T>`. No terminal I/O. |
| Screen rendering | `win_certmgr/screens/` | Maps data to ratatui widgets, handles key input per screen. |
| Multi-step flows | `win_certmgr/actions/` | State machines for import/export/delete that span multiple prompts. |
| Reusable UI | `win_certmgr/widgets/` | Breadcrumb bar, cert table, dialogs -- shared across screens. |
| Existing core | `ssl-toolbox-core` | Format detection (extended with PKCS7), PEM/DER conversion. Called by the win-certstore crate for format work. |

---

## 3. Data Models

### 3.1 Store types (`types.rs`)

```rust
/// A certificate store location (where Windows looks for stores).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreLocation {
    CurrentUser,
    LocalMachine,
    Service(/* service name carried separately */),
    User(/* username carried separately */),
    CurrentService,
}

/// Metadata for a certificate store location selection.
/// Carries the extra context that Service/User locations need.
#[derive(Debug, Clone)]
pub struct StoreLocationContext {
    pub location: StoreLocation,
    /// For Service: the service name. For User: "DOMAIN\username".
    pub qualifier: Option<String>,
}

/// A named certificate store within a location.
#[derive(Debug, Clone)]
pub struct StoreInfo {
    /// Internal Windows name (e.g., "MY", "Root", "CA").
    pub name: String,
    /// Human-readable display name (e.g., "Personal", "Trusted Root CAs").
    pub display_name: String,
    /// Description shown in the UI.
    pub description: String,
}

/// A physical store within a logical store.
#[derive(Debug, Clone)]
pub struct PhysicalStoreInfo {
    /// Physical store name (e.g., ".Default", ".GroupPolicy", ".SmartCard").
    pub name: String,
    /// Flags describing store characteristics.
    pub flags: u32,
}

/// Precise store path for a selected certificate.
/// Used so item-level operations can act on the exact certificate instance
/// the user selected, including physical-store context when applicable.
#[derive(Debug, Clone)]
pub struct StorePath {
    pub location: StoreLocationContext,
    pub store_name: String,
    pub physical_store: Option<String>,
}

/// Opaque handle for an exact certificate context from the Windows store.
/// Internally owns a duplicated PCCERT_CONTEXT and must free it on drop.
///
/// This avoids lossy "re-find by thumbprint" behavior, which is unsafe when a
/// logical store contains duplicate certificates from multiple physical stores.
/// `Clone` must duplicate the underlying context with `CertDuplicateCertificateContext`,
/// not merely copy the raw pointer.
/// `Drop` must release it with `CertFreeCertificateContext`.
#[derive(Debug, Clone)]
pub struct CertHandle {
    pub source: StorePath,
    raw: isize, // PCCERT_CONTEXT
}
```

### 3.2 Certificate types (`types.rs`)

```rust
/// A certificate entry in the store list view.
/// Contains pre-parsed fields for fast rendering without re-parsing DER on every frame.
#[derive(Debug, Clone)]
pub struct CertEntry {
    /// Opaque handle for the exact certificate instance in the Windows store.
    pub handle: CertHandle,
    /// Full DER-encoded certificate bytes (kept for export/detail operations).
    pub der: Vec<u8>,
    /// Parsed subject distinguished name components.
    pub subject: DistinguishedName,
    /// Parsed issuer distinguished name components.
    pub issuer: DistinguishedName,
    /// Subject common name (extracted for fast table rendering).
    pub subject_cn: String,
    /// Issuer common name (extracted for fast table rendering).
    pub issuer_cn: String,
    /// Certificate serial number as colon-separated hex string.
    pub serial: String,
    /// SHA-1 thumbprint as uppercase hex string (e.g., "A1B2C3D4...").
    pub thumbprint_sha1: String,
    /// SHA-256 thumbprint as uppercase hex string.
    pub thumbprint_sha256: String,
    /// Not Before date.
    pub not_before: chrono::NaiveDateTime,
    /// Not After date.
    pub not_after: chrono::NaiveDateTime,
    /// Computed validity status relative to current time.
    pub status: CertStatus,
    /// Subject Alternative Names.
    pub sans: Vec<San>,
    /// Key usage flags (if extension present).
    pub key_usage: Option<Vec<String>>,
    /// Extended key usage OIDs with human-readable names.
    pub extended_key_usage: Option<Vec<ExtKeyUsage>>,
    /// Public key information.
    pub public_key: PublicKeyInfo,
    /// Private key presence detected from store properties.
    /// Provider metadata is loaded lazily when entering the detail view.
    pub private_key: PrivateKeyStatus,
    /// Signature algorithm name and OID.
    pub signature_algorithm: String,
    /// Windows-specific: the friendly name property (may be empty).
    pub friendly_name: Option<String>,
    /// Basic constraints: is this a CA certificate?
    pub is_ca: bool,
}

/// Validity status computed from not_before/not_after relative to now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    Valid,
    /// Certificate has expired.
    Expired,
    /// Certificate is not yet valid (not_before is in the future).
    NotYetValid,
    /// Certificate expires within 30 days.
    ExpiringSoon { days_remaining: u32 },
}

/// Subject Alternative Name entry.
#[derive(Debug, Clone)]
pub enum San {
    Dns(String),
    Ip(std::net::IpAddr),
    Email(String),
    Uri(String),
    Other(String),
}

/// Extended Key Usage with OID and human name.
#[derive(Debug, Clone)]
pub struct ExtKeyUsage {
    /// Numeric OID (e.g., "1.3.6.1.5.5.7.3.1").
    pub oid: String,
    /// Human-readable name (e.g., "Server Authentication").
    pub name: String,
}

/// Distinguished name components.
#[derive(Debug, Clone, Default)]
pub struct DistinguishedName {
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
    pub email: Option<String>,
    /// Full DN string as fallback for unusual fields.
    pub full_dn: String,
}

/// Public key information extracted from the certificate.
#[derive(Debug, Clone)]
pub struct PublicKeyInfo {
    /// Algorithm name (e.g., "RSA", "ECDSA", "Ed25519").
    pub algorithm: String,
    /// Key size in bits (e.g., 2048, 4096, 256).
    pub bit_size: u32,
    /// For RSA: modulus as hex bytes. For EC: curve name + public point.
    pub parameters: PublicKeyParams,
}

#[derive(Debug, Clone)]
pub enum PublicKeyParams {
    Rsa {
        modulus: Vec<u8>,
        exponent: u64,
    },
    Ec {
        curve: String,
        point: Vec<u8>,
    },
    Ed {
        curve: String,
        point: Vec<u8>,
    },
    Other {
        raw: Vec<u8>,
    },
}

/// Private key status as detected from the Windows store (not from parsing).
#[derive(Debug, Clone)]
pub enum PrivateKeyStatus {
    /// No private key associated with this certificate.
    Absent,
    /// Certificate has an associated private key.
    Present,
    /// Store properties suggest a key association exists, but deeper inspection
    /// requires explicit access and was not attempted during list enumeration.
    Inaccessible(String),
}

/// Private key metadata from the Windows key storage provider.
/// Loaded lazily for the selected certificate, not for the entire store view.
#[derive(Debug, Clone)]
pub struct PrivateKeyInfo {
    /// Key storage provider type.
    pub provider: KeyProvider,
    /// Provider name string (e.g., "Microsoft Software Key Storage Provider").
    pub provider_name: String,
    /// Key container name.
    pub container_name: String,
    /// Whether the key is marked exportable.
    pub exportable: bool,
    /// Whether the key requires user interaction to access (strong protection).
    pub user_protected: bool,
    /// Key specification (AT_KEYEXCHANGE, AT_SIGNATURE, or CERT_NCRYPT_KEY_SPEC).
    pub key_spec: KeySpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProvider {
    /// Modern CNG (Cryptography Next Generation) provider.
    Cng,
    /// Legacy CryptoAPI CSP provider.
    CryptoApi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySpec {
    KeyExchange,
    Signature,
    NcryptKey,
}

/// Full private key parameters (only available for exportable keys after explicit inspection).
#[derive(Debug, Clone)]
pub enum PrivateKeyParams {
    Rsa {
        modulus: Vec<u8>,
        exponent: u64,
        prime_p: Vec<u8>,
        prime_q: Vec<u8>,
        dp: Vec<u8>,
        dq: Vec<u8>,
        coefficient: Vec<u8>,
        private_exponent: Vec<u8>,
    },
    Ec {
        curve: String,
        private_key: Vec<u8>,
        public_point: Vec<u8>,
    },
    /// Key parameters could not be extracted (non-exportable, hardware, etc.).
    Unavailable {
        reason: String,
    },
}
```

### 3.3 Import/Export types (`types.rs`)

```rust
/// Supported import/export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertFileFormat {
    Pem,
    Der,
    Pfx,
    Pkcs7,
    Base64,
}

/// Result of analyzing a file before import.
#[derive(Debug, Clone)]
pub struct ImportPreview {
    pub file_path: String,
    pub format: CertFileFormat,
    /// Certificates found in the file (parsed for preview).
    pub certificates: Vec<ImportCertPreview>,
    /// Whether the file contains a private key.
    pub has_private_key: bool,
    /// Target store location and name.
    pub target_location: StoreLocationContext,
    pub target_store: String,
}

/// Options controlling how a file is imported into the target store.
#[derive(Debug, Clone)]
pub struct ImportOptions {
    /// PFX/PKCS12 password, if required.
    pub password: Option<String>,
    /// Whether imported private keys should be marked exportable.
    /// Applies only to PFX/PKCS12 imports that contain private keys.
    pub private_key_exportable: bool,
}

#[derive(Debug, Clone)]
pub struct ImportCertPreview {
    pub subject_cn: String,
    pub issuer_cn: String,
    pub not_after: String,
    pub thumbprint_sha1: String,
}

/// Result of an import operation.
#[derive(Debug, Clone)]
pub struct ImportResult {
    pub certificates_imported: u32,
    pub private_keys_imported: u32,
    /// Certificates that were skipped (already existed, etc.).
    pub skipped: Vec<String>,
    /// Errors encountered (non-fatal, e.g., one cert in a bundle failed).
    pub warnings: Vec<String>,
}

/// Options for exporting a certificate.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub format: CertFileFormat,
    pub output_path: String,
    /// PFX: whether to include the private key.
    pub include_private_key: bool,
    /// PFX: export password.
    pub pfx_password: Option<String>,
    /// PEM/PKCS7: whether to include chain certificates.
    pub include_chain: bool,
}

/// Result of an export operation.
#[derive(Debug, Clone)]
pub struct ExportResult {
    pub output_path: String,
    pub bytes_written: u64,
    pub format: CertFileFormat,
    pub included_private_key: bool,
    pub chain_certs_included: u32,
}
```

### 3.4 Authentication types (`types.rs`)

```rust
/// Current elevation status of the running process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevationStatus {
    /// Running as standard user (no admin privileges).
    Standard,
    /// Running with administrator privileges.
    Elevated,
}

/// An active impersonation context. Must be reverted when done.
#[derive(Debug)]
pub struct ImpersonationContext {
    pub username: String,
    pub domain: String,
    /// The logon token handle. Must be closed on drop.
    token: isize, // HANDLE
}

/// Arguments for re-launching the process elevated, encoding current navigation state.
#[derive(Debug, Clone)]
pub struct RelaunchArgs {
    pub location: String,
    pub store: Option<String>,
    pub viewing_physical: bool,
    pub physical: Option<String>,
    pub thumbprint: Option<String>,
    /// Optional post-resume intent (e.g., "import", "delete", "export").
    /// Only non-sensitive navigation/action state is preserved.
    pub pending_action: Option<String>,
}
```

### 3.5 TUI state types (in `win_certmgr/app.rs`)

```rust
/// Top-level application state for the TUI.
pub struct AppState {
    /// Navigation stack. The last element is the active screen.
    pub nav_stack: Vec<Box<dyn Screen>>,
    /// Currently selected store location (set when user picks one).
    pub current_location: Option<StoreLocationContext>,
    /// Currently selected store name (set when user picks one).
    pub current_store: Option<String>,
    /// Whether we're viewing physical stores vs the logical merged view.
    pub viewing_physical: bool,
    /// Currently selected physical store (if viewing physical).
    pub current_physical: Option<String>,
    /// Loaded certificates for the current store view.
    pub certs: Vec<CertEntry>,
    /// Filtered + sorted view indices into `certs`.
    pub filtered_indices: Vec<usize>,
    /// Currently selected index in the filtered list.
    pub selected_index: usize,
    /// Current page number (0-indexed).
    pub page: usize,
    /// Number of certs per page (computed from terminal height).
    pub page_size: usize,
    /// Active search query string.
    pub search_query: String,
    /// Active filters.
    pub filter: CertFilter,
    /// Current sort configuration.
    pub sort: SortConfig,
    /// Process elevation status (checked once at startup).
    pub elevation: ElevationStatus,
    /// Active impersonation context, if any.
    pub impersonation: Option<ImpersonationContext>,
    /// Whether a modal dialog is currently showing.
    pub active_dialog: Option<DialogState>,
    /// Status message to display temporarily (e.g., "Exported to ~/cert.pem").
    pub status_message: Option<(String, std::time::Instant)>,
    /// Terminal dimensions.
    pub terminal_size: (u16, u16),
}

pub struct CertFilter {
    pub text_query: Option<String>,
    pub status: Option<CertStatus>,
    pub has_private_key: Option<bool>,
    pub key_usage: Option<Vec<String>>,
}

pub struct SortConfig {
    pub column: SortColumn,
    pub ascending: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    SubjectCn,
    IssuerCn,
    Expiry,
    Status,
    Thumbprint,
}

/// Input mode for the TUI (affects how key events are routed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    /// Normal navigation mode. Keys map to actions.
    Normal,
    /// Search input mode. Keys go to the search bar.
    Search,
    /// File path input mode. Keys go to the file input widget.
    FileInput,
    /// Password input mode. Keys go to a password field.
    PasswordInput,
    /// Thumbprint confirmation input mode.
    ThumbprintConfirm,
}

/// State for modal dialogs.
pub enum DialogState {
    Confirm {
        title: String,
        message: String,
        on_confirm: Box<dyn FnOnce(&mut AppState) -> Result<Action>>,
    },
    Error {
        title: String,
        message: String,
        details: Option<String>,
    },
    ImportPreview {
        preview: ImportPreview,
    },
    AuthPrompt {
        username: String,
        password: String,
        focused_field: AuthField,
    },
    ExportFormat {
        selected: usize,
        formats: Vec<(CertFileFormat, &'static str, &'static str)>,
    },
}
```

---

## 4. Library Crate Public API

### 4.1 `store.rs` -- Store Operations

```rust
use crate::types::*;
use crate::error::WinCertResult;

/// List all system store locations available to the current process.
/// Returns the standard locations plus dynamically discovered ones.
pub fn list_store_locations() -> Vec<StoreLocationContext>;

/// Enumerate the named certificate stores at a given location.
/// Uses CertEnumSystemStore under the hood.
/// For Service/User locations, the qualifier is prepended to the store name.
pub fn list_stores(location: &StoreLocationContext) -> WinCertResult<Vec<StoreInfo>>;

/// Enumerate the physical stores within a logical store.
/// Uses CertEnumPhysicalStore under the hood.
pub fn list_physical_stores(
    location: &StoreLocationContext,
    store_name: &str,
) -> WinCertResult<Vec<PhysicalStoreInfo>>;

/// Open a logical certificate store and enumerate all certificates.
/// Returns CertEntry structs with pre-parsed fields for display plus an
/// exact certificate handle for later item-level operations.
/// This is the main data-loading call for the store view.
pub fn open_and_enumerate(
    location: &StoreLocationContext,
    store_name: &str,
) -> WinCertResult<Vec<CertEntry>>;

/// Open a physical certificate store and enumerate all certificates.
pub fn open_physical_and_enumerate(
    location: &StoreLocationContext,
    store_name: &str,
    physical_name: &str,
) -> WinCertResult<Vec<CertEntry>>;

/// Delete the exact selected certificate from the store.
pub fn delete_certificate(cert: &CertHandle) -> WinCertResult<()>;

/// Look up the display name and description for a well-known store name.
/// Returns ("Unknown Store", "") for unrecognized names.
pub fn store_display_info(store_name: &str) -> (&'static str, &'static str);
```

### 4.2 `cert.rs` -- Certificate Parsing

```rust
use crate::types::*;
use crate::error::WinCertResult;

/// Parse a DER-encoded certificate plus its exact store handle into a CertEntry.
/// Uses x509-parser for field extraction.
/// The private_key field is set to Absent -- callers populate lightweight
/// presence information from Windows store properties after parsing.
pub fn parse_cert_der(handle: CertHandle, der: &[u8]) -> WinCertResult<CertEntry>;

/// Compute SHA-1 thumbprint of DER-encoded certificate bytes.
/// Returns uppercase colon-separated hex (e.g., "A1:B2:C3:D4:...").
pub fn thumbprint_sha1(der: &[u8]) -> String;

/// Compute SHA-256 thumbprint of DER-encoded certificate bytes.
pub fn thumbprint_sha256(der: &[u8]) -> String;

/// Compute CertStatus from not_before/not_after relative to now.
pub fn compute_status(
    not_before: chrono::NaiveDateTime,
    not_after: chrono::NaiveDateTime,
) -> CertStatus;

/// Extract public key information from an x509-parser certificate.
pub fn extract_public_key_info(
    cert: &x509_parser::certificate::X509Certificate<'_>,
) -> PublicKeyInfo;

/// Format a distinguished name from x509-parser into our DistinguishedName struct.
pub fn parse_distinguished_name(
    name: &x509_parser::x509::X509Name<'_>,
) -> DistinguishedName;
```

### 4.3 `private_key.rs` -- Private Key Operations

```rust
use crate::types::*;
use crate::error::WinCertResult;

/// Detect private key association for a certificate in the Windows store.
/// Uses certificate properties (CERT_KEY_PROV_INFO_PROP_ID,
/// CERT_KEY_CONTEXT_PROP_ID, CERT_NCRYPT_KEY_HANDLE_PROP_ID) so enumeration
/// does not need to acquire provider handles or trigger smart-card/HSM access.
pub fn detect_private_key(cert: &CertHandle) -> PrivateKeyStatus;

/// Load provider/container/exportability metadata for the selected certificate.
/// This may require opening the provider and should happen lazily from the
/// certificate detail view, not during whole-store enumeration.
pub fn load_private_key_info(cert: &CertHandle) -> WinCertResult<PrivateKeyInfo>;

/// Inspect the full private key parameters for an exportable key.
/// Requires the key to be marked exportable. Returns Unavailable if not.
///
/// For CNG keys: uses NCryptExportKey with BCRYPT_RSAFULLPRIVATE_BLOB or BCRYPT_ECCPRIVATE_BLOB.
/// For CryptoAPI keys: uses CryptExportKey with PRIVATEKEYBLOB.
///
/// This is a privileged operation -- the caller should confirm with the user first.
pub fn inspect_private_key(
    cert: &CertHandle,
) -> WinCertResult<PrivateKeyParams>;
```

### 4.4 `import.rs` -- Import Operations

```rust
use crate::types::*;
use crate::error::WinCertResult;

/// Analyze a file and return a preview of what will be imported.
/// Does not modify the store. Parses the file, detects format,
/// extracts certificate summaries.
pub fn preview_import(
    file_path: &str,
    target_location: &StoreLocationContext,
    target_store: &str,
) -> WinCertResult<ImportPreview>;

/// Execute the import into the specified store.
///
/// PFX/PKCS12: Calls PFXImportCertStore with flags derived from ImportOptions,
///   then copies certs to the target store via CertAddCertificateContextToStore.
/// PEM: Parses all certs from the PEM file, converts each to DER,
///   creates a CertContext, and adds to store.
/// DER: Creates CertContext directly from bytes, adds to store.
/// PKCS7: Parses the PKCS7 structure, extracts certs, adds each to store.
/// Base64: Decodes base64 to DER, then same as DER path.
///
/// Returns summary of what was imported.
pub fn execute_import(
    file_path: &str,
    format: CertFileFormat,
    target_location: &StoreLocationContext,
    target_store: &str,
    options: &ImportOptions,
) -> WinCertResult<ImportResult>;

/// Detect the format of a certificate file.
/// Extends ssl-toolbox-core's detect_format with PKCS7 support.
pub fn detect_import_format(data: &[u8]) -> Option<CertFileFormat>;
```

### 4.5 `export.rs` -- Export Operations

```rust
use crate::types::*;
use crate::error::WinCertResult;

/// Export a single certificate from the store.
///
/// PEM: ctx.to_pem() via schannel, optionally append chain certs.
/// DER: ctx.to_der() via schannel.
/// PFX: Build a temporary CertStore, add the cert (and optionally chain),
///   then CertStore::export_pkcs12(password).
/// PKCS7: Build PKCS7 structure containing the cert (and optionally chain).
/// Base64: ctx.to_der() then base64-encode without PEM headers.
pub fn export_certificate(
    cert: &CertHandle,
    options: &ExportOptions,
) -> WinCertResult<ExportResult>;

/// Export all certificates from a store.
/// Iterates store.certs() and writes them in the chosen format.
/// For PEM: concatenates all certs. For PKCS7: wraps all in one bundle.
/// PFX not supported for bulk export (each cert may have different keys).
pub fn export_all_certificates(
    location: &StoreLocationContext,
    store_name: &str,
    options: &ExportOptions,
) -> WinCertResult<ExportResult>;

/// Attempt to build the certificate chain for a given cert.
/// Uses Windows CertGetCertificateChain API to find intermediates and root.
/// Returns the chain certs in order (leaf first, root last).
pub fn build_chain(
    cert: &CertHandle,
) -> WinCertResult<Vec<Vec<u8>>>;
```

### 4.6 `auth.rs` -- Authentication & Elevation

```rust
use crate::types::*;
use crate::error::WinCertResult;

/// Check whether the current process is running elevated (admin).
/// Calls windows_sys::Win32::UI::Shell::IsUserAnAdmin().
pub fn check_elevation() -> ElevationStatus;

/// Check whether a specific operation will require elevation.
/// Based on the target location and whether it's a read or write.
pub fn requires_elevation(
    location: &StoreLocationContext,
    write: bool,
) -> bool;

/// Re-launch the current process with administrator privileges.
/// Uses ShellExecuteW with "runas" verb.
/// Encodes the provided resume args into CLI arguments so the new process
/// can resume at the same navigation state.
///
/// Returns Ok(()) if the elevated process was launched (this process should exit).
/// Returns Err if the UAC prompt was cancelled or failed.
pub fn relaunch_elevated(resume: &RelaunchArgs) -> WinCertResult<()>;

/// Impersonate another user to access their certificate store.
/// Calls LogonUser with LOGON32_LOGON_INTERACTIVE, then ImpersonateLoggedOnUser.
/// Returns an ImpersonationContext that reverts on drop.
pub fn impersonate_user(
    username: &str,
    domain: &str,
    password: &str,
) -> WinCertResult<ImpersonationContext>;

/// Explicitly revert impersonation. Called automatically on ImpersonationContext drop.
pub fn revert_impersonation(context: &ImpersonationContext) -> WinCertResult<()>;
```

---

## 5. Windows API Call Map

Exact Win32 functions needed, which crate provides them, and how they're called.

### 5.1 Store enumeration (via `windows-sys`)

**`CertEnumSystemStore`** -- Lists store names at a location.

```rust
// windows_sys::Win32::Security::Cryptography::CertEnumSystemStore
unsafe fn CertEnumSystemStore(
    dwFlags: u32,                    // e.g., CERT_SYSTEM_STORE_CURRENT_USER
    pvSystemStoreLocationPara: *const c_void, // NULL for CurrentUser/LocalMachine
    pvArg: *mut c_void,             // Callback context pointer
    pfnEnum: PFN_CERT_ENUM_SYSTEM_STORE, // Callback function
) -> BOOL;
```

Callback receives `pvSystemStore` (wide string store name) and `dwFlags`. Accumulate store names into a `Vec<String>` passed via `pvArg`.

**`CertEnumPhysicalStore`** -- Lists physical stores within a logical store.

```rust
// windows_sys::Win32::Security::Cryptography::CertEnumPhysicalStore
unsafe fn CertEnumPhysicalStore(
    pvSystemStore: *const c_void,   // Wide string logical store name
    dwFlags: u32,                    // Location flags
    pvArg: *mut c_void,             // Callback context
    pfnEnum: PFN_CERT_ENUM_PHYSICAL_STORE, // Callback
) -> BOOL;
```

### 5.2 Store open (via `schannel` + `windows-sys`)

**Standard stores** -- Use `schannel`:

```rust
let store = CertStore::open_current_user("MY")?;    // CurrentUser
let store = CertStore::open_local_machine("Root")?;  // LocalMachine
```

**Service/User/Physical stores** -- Use `windows-sys` directly, then duplicate
each enumerated `PCCERT_CONTEXT` into an owned `CertHandle` before the store is closed:

```rust
// Service store: "ServiceName\MY"
let store_name: Vec<u16> = "MyService\\MY\0".encode_utf16().collect();
unsafe {
    CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        0,  // hCryptProv
        CERT_SYSTEM_STORE_SERVICES | CERT_STORE_OPEN_EXISTING_FLAG,
        store_name.as_ptr() as *const c_void,
    )
}

// User store: "username\MY"
// Same pattern with CERT_SYSTEM_STORE_USERS flag.

// Physical store:
unsafe {
    CertOpenStore(
        CERT_STORE_PROV_PHYSICAL_W,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
        "Root\\.Default\0".encode_utf16().collect::<Vec<u16>>().as_ptr() as _,
    )
}
```

### 5.3 Certificate enumeration (via `schannel`)

```rust
let store = CertStore::open_current_user("MY")?;
for cert_ctx in store.certs() {
    let der: &[u8] = cert_ctx.to_der();
    let friendly_name: Option<String> = cert_ctx.friendly_name();
    let thumbprint: Vec<u8> = cert_ctx.sha1();
    // Parse DER with x509-parser for display fields
    // Detect private key with cert_ctx.private_key()
}
```

### 5.4 Private key detection (via `windows-sys`)

```rust
// Presence check during enumeration:
let has_key = has_cert_property(ctx, CERT_KEY_PROV_INFO_PROP_ID)
    || has_cert_property(ctx, CERT_KEY_CONTEXT_PROP_ID)
    || has_cert_property(ctx, CERT_NCRYPT_KEY_HANDLE_PROP_ID);

// Deeper metadata load only in detail view:
match open_private_key_provider_for_selected_cert(&cert_handle) {
    Ok(provider) => { /* populate PrivateKeyInfo */ }
    Err(err) => { /* show info unavailable / access denied in detail view */ }
}
```

### 5.5 Private key parameter extraction (via `windows-sys`)

**CNG keys** -- `NCryptExportKey`:

```rust
use windows_sys::Win32::Security::Cryptography::{
    NCryptExportKey, BCRYPT_RSAFULLPRIVATE_BLOB, NCRYPT_ALLOW_EXPORT_FLAG,
};

// Get handle from schannel's NcryptKey
// 1. Call NCryptExportKey with NULL output to get required size
// 2. Allocate buffer
// 3. Call NCryptExportKey to fill buffer
// 4. Parse the BCRYPT_RSAKEY_BLOB header + raw key material
```

**CryptoAPI keys** -- `CryptExportKey`:

```rust
use windows_sys::Win32::Security::Cryptography::{
    CryptExportKey, PRIVATEKEYBLOB,
};

// 1. Call CryptExportKey with NULL to get size
// 2. Allocate buffer
// 3. Call CryptExportKey to fill buffer
// 4. Parse the PUBLICKEYSTRUC + RSAPUBKEY header + raw key material
```

### 5.6 Import operations

**PFX import** (via `windows-sys`):

```rust
let mut flags = PKCS12_INCLUDE_EXTENDED_PROPERTIES;
flags |= match target_location.location {
    StoreLocation::LocalMachine => CRYPT_MACHINE_KEYSET,
    _ => CRYPT_USER_KEYSET,
};
if options.private_key_exportable {
    flags |= CRYPT_EXPORTABLE;
}
let temp_store = PFXImportCertStore(&blob, password_wide.as_ptr(), flags)?;
// Copy imported contexts to the target store
```

**DER/PEM import** (via `windows-sys`):

```rust
// Convert PEM to DER if needed (using ssl-toolbox-core or x509-parser)
// Create cert context from DER bytes:
unsafe {
    let ctx = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        der.as_ptr(),
        der.len() as u32,
    );
    // Add to store:
    CertAddCertificateContextToStore(
        store_handle,
        ctx,
        CERT_STORE_ADD_REPLACE_EXISTING,
        std::ptr::null_mut(),
    );
    CertFreeCertificateContext(ctx);
}
```

**PKCS7 import** (via `windows-sys`):

```rust
// Open a PKCS7 store from the data:
let pkcs7_blob = CRYPT_DATA_BLOB {
    cbData: data.len() as u32,
    pbData: data.as_ptr() as *mut u8,
};
let pkcs7_store = unsafe {
    CertOpenStore(
        CERT_STORE_PROV_PKCS7,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        0,
        &pkcs7_blob as *const _ as *const c_void,
    )
};
// Enumerate certs from pkcs7_store and add each to target store
```

### 5.7 Export operations

**PFX export** (via `schannel`):

```rust
// Build a temp store with the exact selected cert + chain
let temp_store = CertStore::new()?; // memory store
temp_store.add_cert(selected_cert_context, CertAdd::Always)?;
// Add chain certs if requested
let pfx_bytes = temp_store.export_pkcs12(password)?;
std::fs::write(path, pfx_bytes)?;
```

**PKCS7 export** (via `windows-sys`):

```rust
// Use CryptSignMessage or build PKCS7 manually using the certs.
// Alternatively, use openssl from ssl-toolbox-core to build PKCS7
// from the DER bytes of each certificate.
```

### 5.8 Authentication (via `windows-sys`)

**Elevation check:**

```rust
use windows_sys::Win32::UI::Shell::IsUserAnAdmin;
let elevated = unsafe { IsUserAnAdmin() } != 0;
```

**UAC re-launch:**

```rust
use windows_sys::Win32::UI::Shell::ShellExecuteW;

let exe_path = std::env::current_exe()?;
let args = format!("--certmgr --location local-machine --store MY");
// Convert to wide strings
unsafe {
    ShellExecuteW(
        0,                    // hwnd
        w!("runas"),          // lpOperation
        exe_wide.as_ptr(),    // lpFile
        args_wide.as_ptr(),   // lpParameters
        std::ptr::null(),     // lpDirectory
        SW_SHOWNORMAL,        // nShowCmd
    );
}
```

**User impersonation:**

```rust
use windows_sys::Win32::Security::{
    LogonUserW, ImpersonateLoggedOnUser, RevertToSelf,
    LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
};

let mut token: HANDLE = 0;
let success = unsafe {
    LogonUserW(
        username_wide.as_ptr(),
        domain_wide.as_ptr(),
        password_wide.as_ptr(),
        LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT,
        &mut token,
    )
};
if success != 0 {
    unsafe { ImpersonateLoggedOnUser(token); }
    // Return ImpersonationContext { token }
}

// On revert (ImpersonationContext::drop):
unsafe {
    RevertToSelf();
    CloseHandle(token);
}
```

---

## 6. Error Handling

### 6.1 Error type (`error.rs`)

```rust
use std::fmt;

pub type WinCertResult<T> = Result<T, WinCertError>;

#[derive(Debug)]
pub enum WinCertError {
    /// A Windows API call failed. Contains the function name and HRESULT/Win32 error code.
    WindowsApi {
        function: &'static str,
        code: u32,
        message: String,
    },
    /// Certificate store could not be opened.
    StoreOpenFailed {
        location: String,
        store: String,
        code: u32,
    },
    /// Certificate parsing failed (malformed DER, etc.).
    ParseError {
        detail: String,
    },
    /// Private key operation failed.
    PrivateKeyError {
        detail: String,
    },
    /// File I/O error.
    IoError(std::io::Error),
    /// Elevation required but not available.
    ElevationRequired {
        operation: String,
    },
    /// User cancelled the UAC prompt or auth dialog.
    UserCancelled,
    /// Access denied (permissions insufficient even with correct auth).
    AccessDenied {
        operation: String,
        code: u32,
    },
    /// Import format not recognized.
    UnrecognizedFormat {
        path: String,
    },
    /// Export failed (key not exportable, etc.).
    ExportFailed {
        detail: String,
    },
    /// Impersonation failed.
    ImpersonationFailed {
        username: String,
        code: u32,
    },
}

impl fmt::Display for WinCertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WindowsApi { function, code, message } => {
                write!(f, "Windows API error in {}: 0x{:08X} - {}", function, code, message)
            }
            Self::StoreOpenFailed { location, store, code } => {
                write!(f, "Failed to open store {}\\{}: 0x{:08X}", location, store, code)
            }
            Self::ParseError { detail } => write!(f, "Certificate parse error: {}", detail),
            Self::PrivateKeyError { detail } => write!(f, "Private key error: {}", detail),
            Self::IoError(e) => write!(f, "I/O error: {}", e),
            Self::ElevationRequired { operation } => {
                write!(f, "Administrator privileges required for: {}", operation)
            }
            Self::UserCancelled => write!(f, "Operation cancelled by user"),
            Self::AccessDenied { operation, code } => {
                write!(f, "Access denied for {}: 0x{:08X}", operation, code)
            }
            Self::UnrecognizedFormat { path } => {
                write!(f, "Could not determine certificate format of: {}", path)
            }
            Self::ExportFailed { detail } => write!(f, "Export failed: {}", detail),
            Self::ImpersonationFailed { username, code } => {
                write!(f, "Failed to impersonate {}: 0x{:08X}", username, code)
            }
        }
    }
}

impl std::error::Error for WinCertError {}

impl From<std::io::Error> for WinCertError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}
```

### 6.2 Windows error code helper (`win32.rs`)

```rust
use windows_sys::Win32::Foundation::GetLastError;

/// Get the last Win32 error code and format it into a human-readable message.
pub unsafe fn last_error() -> (u32, String) {
    let code = GetLastError();
    let message = format_win32_error(code);
    (code, message)
}

/// Format a Win32 error code into a message using FormatMessageW.
pub fn format_win32_error(code: u32) -> String {
    // Use FormatMessageW with FORMAT_MESSAGE_FROM_SYSTEM
    // ...implementation...
}

/// Common error codes mapped to actionable messages.
pub fn actionable_message(code: u32) -> &'static str {
    match code {
        0x80070005 => "Access is denied. Run as Administrator or check store permissions.",
        0x80092004 => "Cannot find object or property. The certificate or key may not exist.",
        0x80090016 => "The keyset is not defined. The private key container may be missing.",
        0x80090029 => "The requested operation is not supported by the key storage provider.",
        _ => "An unexpected error occurred.",
    }
}
```

---

## 7. Navigation & Screen Architecture

### 7.1 Stack-based navigation

Each screen pushes onto `nav_stack: Vec<Box<dyn Screen>>`. "Back" (Esc/Backspace) pops. The breadcrumb bar renders labels from all screens in the stack.

### 7.2 Screen flow

```
Main Menu (cliclack)
  --> Windows Certificate Manager (ratatui takes over)
        |
        +-- LocationScreen
        |     +-- Current User
        |     +-- Local Machine
        |     +-- Service: [prompts for service name]
        |     +-- User: [prompts for credentials via AuthPrompt dialog]
        |
        +-- StoreListScreen (for chosen location)
        |     +-- Personal (MY)
        |     +-- Trusted Root CAs (Root)
        |     +-- Intermediate CAs (CA)
        |     +-- Trusted People
        |     +-- Trusted Publishers
        |     +-- Enterprise Trust
        |     +-- Untrusted (Disallowed)
        |     +-- [dynamically discovered stores via CertEnumSystemStore]
        |
        +-- StoreViewScreen (logical) ---- [Tab] ---- PhysicalScreen
        |     |                                         +-- .Default
        |     |                                         +-- .GroupPolicy
        |     |                                         +-- .LocalMachine
        |     |                                         +-- .SmartCard
        |     |
        |     +-- Paginated cert table
        |     +-- Search/filter bar
        |     +-- Actions: [i]mport  [e]xport all  [r]efresh
        |
        +-- CertDetailScreen
        |     +-- Scrollable detail view
        |     +-- Lazy load private key metadata for selected cert
        |     +-- Actions: [e]xport  [d]elete  [k] inspect key
        |
        +-- KeyInspectScreen (overlay on CertDetailScreen)
              +-- Full private key parameters
```

### 7.3 Screen lifecycle

```
                    ┌─────────────────────────────────────────┐
                    │              AppState                     │
                    │                                           │
Enter CertMgr ──>  │  nav_stack: [LocationScreen]              │
                    │                                           │
User picks ──────>  │  nav_stack: [LocationScreen,             │
"Local Machine"     │             StoreListScreen]              │
                    │  current_location: LocalMachine           │
                    │                                           │
User picks ──────>  │  nav_stack: [LocationScreen,             │
"Personal (MY)"     │             StoreListScreen,             │
                    │             StoreViewScreen]              │
                    │  current_store: "MY"                      │
                    │  certs: [loaded from store]               │
                    │                                           │
User selects ────>  │  nav_stack: [LocationScreen,             │
a certificate       │             StoreListScreen,             │
                    │             StoreViewScreen,             │
                    │             CertDetailScreen]            │
                    │                                           │
User presses ────>  │  nav_stack: [LocationScreen,             │
Esc (back)          │             StoreListScreen,             │
                    │             StoreViewScreen]              │
                    │                                           │
User presses q ──>  │  break loop, ratatui::restore()          │
                    │  return to cliclack menu                  │
                    └─────────────────────────────────────────┘
```

### 7.4 Breadcrumb rendering

The breadcrumb bar concatenates `screen.breadcrumb_label()` from all screens in the stack, separated by ` > `, prefixed with elevation status.

Examples:
```
Windows Cert Manager [User Mode] > Local Machine > Personal (MY)
Windows Cert Manager [Administrator] > Current User > Root > CN=DigiCert Global Root G2
Windows Cert Manager [User Mode] > Service: IIS > Personal (MY)
Windows Cert Manager [User Mode] > User: CORP\jdoe > Personal (MY)
```

### 7.5 Key bindings

| Key | Context | Action |
|-----|---------|--------|
| Up/Down or j/k | List screens | Navigate selection |
| Enter | List screens | Select / drill in |
| Esc | Any (Normal mode) | Go back one level (or quit from LocationScreen) |
| Backspace | Any (Normal mode) | Go back one level |
| / | StoreView | Enter search mode |
| Esc | Search mode | Cancel search, return to Normal |
| Enter | Search mode | Apply search, return to Normal |
| f | StoreView | Cycle filter options |
| Tab | StoreView | Toggle logical/physical view |
| i | StoreView | Start import flow |
| e | StoreView | Export all certificates |
| e | CertDetail | Export this certificate |
| d | CertDetail | Start delete flow |
| k | CertDetail | Inspect private key |
| v | CertDetail | Expand/collapse truncated values |
| s | StoreView | Cycle sort column: Subject -> Issuer -> Expiry -> Status -> Thumbprint |
| S | StoreView | Reverse sort direction |
| n or Right | StoreView | Next page |
| p or Left | StoreView | Previous page |
| r | StoreView | Refresh (re-read store) |
| q | Any (Normal mode) | Quit back to cliclack main menu |
| ? | Any | Show help overlay |

---

## 8. Certificate List & Filtering

### 8.1 Table layout

```
╭─ Local Machine > Personal (MY) ──────────────────────────────── [User Mode] ╮
│                                                                               │
│ Search: server*                                                    [/] search │
│                                                                               │
│  #  │ Subject CN              │ Issuer CN         │ Expires    │ St │ K │ Thumb │
│ ────┼─────────────────────────┼───────────────────┼────────────┼────┼───┼─────── │
│   1 │ server.example.com      │ DigiCert G2       │ 2026-12-01 │ OK │ K │ A1B2… │
│ > 2 │ *.internal.corp         │ Internal CA       │ 2025-01-15 │ EX │ K │ D4E5… │
│   3 │ mail.example.com        │ Let's Encrypt     │ 2026-08-20 │ OK │   │ 7A8B… │
│     │                         │                   │            │    │   │       │
│     │                         │                   │            │    │   │       │
│                                                                               │
│ Page 1/12 │ 294 total │ 47 shown │ Sort: Subject ↑     [i]mport [e]xport [?]help│
╰──────────────────────────────────────────────────────────────────────────────────╯
```

**Status column abbreviations** (colored):
- `OK` (green) -- Valid
- `EX` (red) -- Expired
- `NY` (yellow) -- Not Yet Valid
- `30` (orange) -- Expiring within 30 days (shows days remaining)

**Key column**: `K` if private key present, blank if not.

**Thumbprint column**: First 8 hex chars of SHA-1, truncated with ellipsis.

### 8.2 Column widths

Columns resize based on terminal width. Priority order for truncation (truncated first):

1. Thumbprint (minimum 8 chars + ellipsis)
2. Issuer CN (minimum 10 chars)
3. Subject CN (minimum 15 chars)
4. The `#`, `Expires`, `Status`, and `Key` columns have fixed widths

Minimum supported terminal width: 80 columns. Below that, hide Thumbprint column entirely.

### 8.3 Filtering implementation

```rust
impl AppState {
    /// Recompute filtered_indices from certs based on current filter + search.
    fn apply_filter_and_sort(&mut self) {
        self.filtered_indices = self.certs.iter().enumerate()
            .filter(|(_, cert)| self.matches_filter(cert))
            .map(|(i, _)| i)
            .collect();

        self.filtered_indices.sort_by(|&a, &b| {
            let cmp = self.compare_certs(&self.certs[a], &self.certs[b]);
            if self.sort.ascending { cmp } else { cmp.reverse() }
        });

        // Reset to page 0 after filter change
        self.page = 0;
        self.selected_index = 0;
    }

    fn matches_filter(&self, cert: &CertEntry) -> bool {
        // Text query: match against subject_cn, issuer_cn, SANs, thumbprint
        if let Some(ref query) = self.filter.text_query {
            let q = query.to_lowercase();
            let matches = cert.subject_cn.to_lowercase().contains(&q)
                || cert.issuer_cn.to_lowercase().contains(&q)
                || cert.thumbprint_sha1.to_lowercase().contains(&q)
                || cert.sans.iter().any(|s| s.to_string().to_lowercase().contains(&q));
            if !matches { return false; }
        }
        // Status filter
        if let Some(ref status) = self.filter.status {
            if std::mem::discriminant(&cert.status) != std::mem::discriminant(status) {
                return false;
            }
        }
        // Private key filter
        if let Some(has_key) = self.filter.has_private_key {
            let cert_has_key = matches!(cert.private_key, PrivateKeyStatus::Present);
            if cert_has_key != has_key { return false; }
        }
        true
    }
}
```

### 8.4 Pagination

- `page_size` computed as `(terminal_height - chrome_rows) / 1` where `chrome_rows` = breadcrumb (1) + search bar (1) + table header (2) + footer (2) + border (2) = ~8
- Default page_size caps at 25 even on tall terminals (readability)
- Footer shows: `Page {page+1}/{total_pages} | {total} total | {filtered} shown | Sort: {column} {arrow}`

---

## 9. Certificate Detail View

### 9.1 Layout

Full-screen scrollable view. Content is a list of `(label, value)` sections rendered into a scrollable viewport.

```
╭─ ... > Personal (MY) > CN=server.example.com ─────────── [User Mode] ╮
│                                                                        │
│  Subject                                                               │
│    CN = server.example.com                                             │
│    O  = Example Corp                                                   │
│    OU = Engineering                                                    │
│    L  = San Francisco                                                  │
│    S  = California                                                     │
│    C  = US                                                             │
│                                                                        │
│  Issuer                                                                │
│    CN = DigiCert SHA2 Extended Validation Server CA                    │
│    O  = DigiCert Inc                                                   │
│                                                                        │
│  Validity                                                              │
│    Not Before : 2025-06-15 00:00:00 UTC                               │
│    Not After  : 2026-12-01 23:59:59 UTC                               │
│    Status     : Valid (236 days remaining)                             │
│                                                                        │
│  Serial Number                                                         │
│    0A:1B:2C:3D:4E:5F:6A:7B:8C:9D:0E:1F:2A:3B:4C:5D                  │
│                                                                        │
│  Thumbprint                                                            │
│    SHA-1   : A1:B2:C3:D4:E5:F6:78:90:AB:CD:EF:12:34:56:78:90:AB:... │
│    SHA-256 : 12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:... │
│                                                                        │
│  Subject Alternative Names                                             │
│    DNS : server.example.com                                            │
│    DNS : www.example.com                                               │
│    IP  : 10.0.1.50                                                     │
│                                                                        │
│  Key Usage                                                             │
│    Digital Signature, Key Encipherment                                 │
│                                                                        │
│  Extended Key Usage                                                    │
│    Server Authentication   (1.3.6.1.5.5.7.3.1)                        │
│    Client Authentication   (1.3.6.1.5.5.7.3.2)                        │
│                                                                        │
│  Public Key                                                            │
│    Algorithm : RSA (2048 bit)                                          │
│    Exponent  : 65537                                                   │
│    Modulus   : 00:B4:3A:7F:... [press 'v' to expand]                  │
│                                                                        │
│  Private Key                                                           │
│    Present    : Yes                                                    │
│    Provider   : Microsoft Software Key Storage Provider (CNG)          │
│    Container  : le-server-example-com-2025                             │
│    Exportable : Yes                                                    │
│    Protected  : No                                                     │
│    [press 'k' to inspect full private key parameters]                  │
│                                                                        │
│  Signature Algorithm                                                   │
│    SHA256withRSA (1.2.840.113549.1.1.11)                              │
│                                                                        │
│  Basic Constraints                                                     │
│    CA : No                                                             │
│                                                                        │
│  Friendly Name                                                         │
│    server.example.com                                                  │
│                                                                        │
├────────────────────────────────────────────────────────────────────────┤
│ [e]xport  [d]elete  [k] inspect key  [v] expand  ↑↓ scroll  [Esc] back│
╰────────────────────────────────────────────────────────────────────────╯
```

### 9.2 Scroll behavior

- `j/k` or `Up/Down` scrolls the viewport by one line
- `PgUp/PgDn` scrolls by viewport height
- `Home/End` jumps to top/bottom
- Scroll position shown as a vertical scroll indicator on the right border

### 9.3 Value expansion (`v` key)

Toggle between truncated and full-length display for long values:
- RSA modulus: truncated shows first 16 bytes + `...`, expanded shows all bytes in 16-byte rows
- Thumbprints: always full by default (they're short enough)
- Public key point (EC): same truncation pattern

### 9.4 Private key inspection (`k` key)

When entering `CertDetailScreen`, the app attempts a lazy `load_private_key_info()`
for the selected certificate handle. If that succeeds, provider/container/exportability
metadata is shown in the detail panel. If it fails, the detail panel shows:

```text
Present    : Yes
Details    : Unavailable until explicit access succeeds
Reason     : Smart card, HSM, or permissions may block provider inspection
```

Pressing `k` then performs the explicit, privileged `inspect_private_key()` call
against the selected certificate handle and opens a modal overlay:

```
╭─ Private Key Inspection ──────────────────────────────────╮
│                                                            │
│  ⚠  Accessing private key material                        │
│                                                            │
│  Type        : RSA 2048-bit (CNG)                          │
│  Provider    : Microsoft Software Key Storage Provider      │
│  Container   : le-server-example-com-2025                  │
│  Exportable  : Yes                                         │
│                                                            │
│  Modulus     : 00:B4:3A:7F:D2:1E:9C:8B:F0:A5:...         │
│               (full hex, 16 bytes per line)                │
│  Exponent   : 65537                                        │
│  Prime P    : 00:E7:2A:... (full hex)                      │
│  Prime Q    : 00:D1:8B:... (full hex)                      │
│  d mod p-1  : ... (full hex)                               │
│  d mod q-1  : ... (full hex)                               │
│  Coefficient: ... (full hex)                               │
│  Priv Exp   : ... (full hex)                               │
│                                                            │
│                                    [Esc] close             │
╰────────────────────────────────────────────────────────────╯
```

If key is not exportable:

```
╭─ Private Key Inspection ──────────────────────────────────╮
│                                                            │
│  Type        : RSA 2048-bit (CNG)                          │
│  Provider    : Microsoft Software Key Storage Provider      │
│  Exportable  : No                                          │
│                                                            │
│  ⚠  Private key parameters are not accessible.             │
│     The key was imported without the exportable flag.       │
│     Only the public key components are available from       │
│     the certificate's public key info section.              │
│                                                            │
│                                    [Esc] close             │
╰────────────────────────────────────────────────────────────╯
```

---

## 10. Import Operations

### 10.1 Import flow state machine

```
[User presses 'i' on StoreViewScreen]
         |
         v
  FileInputDialog ──> user types path ──> Validate file exists
         |                                       |
         |  (Esc: cancel)                 (file not found: error dialog)
         v
  detect_import_format(data)
         |
         +─ PFX ──> PasswordDialog ──> ConfirmDialog(exportable?) ──> preview_import()
         |                                                             |
         +─ PEM ──────────────────> preview_import()
         |                                    |
         +─ DER ──────────────────> preview_import()
         |                                    |
         +─ PKCS7 ────────────────> preview_import()
         |                                    |
         +─ Base64 ───────────────> preview_import()
         |                                    |
         +─ None ─────> ErrorDialog("Unrecognized format")
         |
         v
  ImportPreviewDialog
         |
         +─ Enter: confirm ──> requires_elevation()? ──> AuthFlow ──> execute_import()
         |                                                                  |
         +─ Esc: cancel                                              ImportResultDialog
                                                                           |
                                                                     refresh certs
```

### 10.2 File path input

The `FileInputDialog` provides:
- Text input for the file path
- Tab-completion for directories and files
- Validation that the path exists and is readable
- Filter for known extensions: `.pfx`, `.p12`, `.pem`, `.crt`, `.cer`, `.der`, `.p7b`, `.p7c`, `.b64`

### 10.3 Format detection extension

The import format detector extends `ssl-toolbox-core::convert::detect_format()` with
explicit PEM PKCS7 recognition and returns `None` when the input is unsupported:

```rust
pub fn detect_import_format(data: &[u8]) -> Option<CertFileFormat> {
    // 1. PEM-encoded PKCS7/P7B
    if is_pkcs7_pem(data) { return Some(CertFileFormat::Pkcs7); }

    // 2. Regular PEM certificate / PEM bundle
    if is_pem_cert_bundle(data) { return Some(CertFileFormat::Pem); }

    // 3. Try PKCS7 DER (ASN.1 OID 1.2.840.113549.1.7.2 = signedData)
    //    The DER encoding starts with SEQUENCE { OID, ... }
    if is_pkcs7_der(data) { return Some(CertFileFormat::Pkcs7); }

    // 4. Try PKCS12 (uses schannel or openssl)
    if is_pkcs12(data) { return Some(CertFileFormat::Pfx); }

    // 5. Try DER certificate
    if is_der_cert(data) { return Some(CertFileFormat::Der); }

    // 6. Try base64 (no headers)
    if is_base64(data) { return Some(CertFileFormat::Base64); }

    None
}

fn is_pkcs7_pem(data: &[u8]) -> bool {
    std::str::from_utf8(data)
        .map(|text| text.contains("-----BEGIN PKCS7-----"))
        .unwrap_or(false)
}

fn is_pem_cert_bundle(data: &[u8]) -> bool {
    std::str::from_utf8(data)
        .map(|text| text.contains("-----BEGIN CERTIFICATE-----"))
        .unwrap_or(false)
}

fn is_pkcs7_der(data: &[u8]) -> bool {
    // PKCS7 signedData OID: 06 09 2A 86 48 86 F7 0D 01 07 02
    // Look for this OID within the first 30 bytes of the ASN.1 structure
    let oid_bytes: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
    data.len() > 30 && data[..30].windows(oid_bytes.len()).any(|w| w == oid_bytes)
}
```

### 10.3.1 PFX import policy

If the selected file is PFX/PKCS12 and contains a private key, the flow must ask:

```text
Import private key as exportable?
> No (recommended)
  Yes
```

This maps directly to the `CRYPT_EXPORTABLE` flag at import time. The choice is
explicit because Windows does not allow changing exportability after import.

Key persistence flags must also be explicit:
- `CurrentUser` and impersonated user imports use `CRYPT_USER_KEYSET`
- `LocalMachine` and service-store imports use `CRYPT_MACHINE_KEYSET`
- Machine-key imports must rely on Windows ACL behavior for the target key container

### 10.4 Import preview dialog

```
╭─ Import Preview ──────────────────────────────────────────╮
│                                                            │
│  File     : C:\certs\server.pfx                            │
│  Format   : PKCS12 (PFX)                                  │
│  Contains : 1 certificate + private key                    │
│             2 CA certificates (chain)                      │
│  Target   : Local Machine > Personal (MY)                  │
│                                                            │
│  Certificates:                                             │
│    1. CN=server.example.com  (expires 2026-12-01)          │
│    2. CN=DigiCert G2 CA      (expires 2031-03-08)          │
│    3. CN=DigiCert Root       (expires 2038-01-15)          │
│                                                            │
│  [Enter] import  [Esc] cancel                              │
╰────────────────────────────────────────────────────────────╯
```

---

## 11. Export Operations

### 11.1 Export from cert detail

```
[User presses 'e' on CertDetailScreen]
         |
         v
  ExportFormatDialog
    > PEM (.pem)           - Base64 encoded
      DER (.der)           - Binary encoded
      PFX/PKCS12 (.pfx)   - Certificate + private key
      PKCS7/P7B (.p7b)    - Certificate chain bundle
      Base64 (.b64)        - Raw base64, no headers
         |
         v (user picks format)
  Format-specific prompts:
    PFX: "Include private key?" ──> Yes: "Set export password" (PasswordDialog)
                                    No: cert-only PFX
         If key not exportable: warn dialog, offer cert-only
    PKCS7: "Include chain?" ──> Yes: build_chain() + bundle
    PEM: "Include chain?" ──> Yes: build_chain() + concatenate
         |
         v
  FileOutputDialog (path prompt with smart default)
    Default: ~/Downloads/{subject_cn}.{ext}
    Replaces invalid filename chars with underscore
         |
         v
  requires_elevation()? ──> AuthFlow
         |
         v
  export_certificate() ──> ExportResultDialog
    "Exported to C:\Users\jared\Downloads\server.example.com.pem (2,048 bytes)"
```

### 11.2 Export all from store view

```
[User presses 'e' on StoreViewScreen]
         |
         v
  ExportFormatDialog (PFX not available for bulk)
    > PEM (.pem)     - All certs concatenated
      DER (.der)     - One file per cert (creates directory)
      PKCS7/P7B     - All certs in one bundle
      Base64 (.b64)  - All certs concatenated
         |
         v
  FileOutputDialog
    PEM/PKCS7/Base64: single output file
    DER: output directory (each cert saved as {thumbprint_first8}.der)
         |
         v
  export_all_certificates()
```

### 11.3 Smart default filenames

```rust
fn default_export_filename(cert: &CertEntry, format: CertFileFormat) -> String {
    let safe_cn = cert.subject_cn
        .replace(|c: char| !c.is_alphanumeric() && c != '-' && c != '.', "_");

    let ext = match format {
        CertFileFormat::Pem => "pem",
        CertFileFormat::Der => "der",
        CertFileFormat::Pfx => "pfx",
        CertFileFormat::Pkcs7 => "p7b",
        CertFileFormat::Base64 => "b64",
    };

    format!("{}.{}", safe_cn, ext)
}
```

---

## 12. Delete Operations

### 12.1 Delete flow

```
[User presses 'd' on CertDetailScreen]
         |
         v
  requires_elevation()? ──> AuthFlow
         |
         v
  DeleteConfirmDialog
╭─ Confirm Delete ──────────────────────────────────────────╮
│                                                            │
│  ⚠  You are about to delete this certificate:              │
│                                                            │
│    CN = server.example.com                                 │
│    Store: Local Machine > Personal (MY)                    │
│    Thumbprint: A1:B2:C3:D4:E5:F6:78:90:AB:CD:EF:...      │
│                                                            │
│  This action cannot be undone.                             │
│                                                            │
│  Type the first 8 characters of the thumbprint             │
│  to confirm: A1B2C3D4                                      │
│                                                            │
│  > ________                                                │
│                                                            │
│  [Enter] confirm  [Esc] cancel                             │
╰────────────────────────────────────────────────────────────╯

         |
         v (user types matching thumbprint)
  delete_certificate(&selected_cert.handle)
         |
         v
  Success dialog ──> pop back to StoreViewScreen ──> refresh certs
```

### 12.2 Thumbprint confirmation

The user must type exactly the first 8 hex characters (uppercase, no colons) of the SHA-1 thumbprint. Input is validated character-by-character. Mismatched input shows red highlight. This prevents accidental deletion, particularly important in Root and CA stores.

---

## 13. Authentication & Elevation

### 13.1 Elevation detection on entry

When `launch_certmgr()` is called, immediately check elevation:

```rust
let elevation = ssl_toolbox_win_certstore::auth::check_elevation();
```

This is stored in `AppState.elevation` and displayed in the breadcrumb bar:
- `[User Mode]` -- standard user
- `[Administrator]` -- elevated

### 13.2 Pre-operation elevation check

Before any write operation (import, delete, export with private key on LocalMachine), the action checks:

```rust
if auth::requires_elevation(&state.current_location, true) 
    && state.elevation == ElevationStatus::Standard 
{
    // Show elevation dialog
}
```

### 13.3 UAC re-launch flow

```
╭─ Elevation Required ──────────────────────────────────────╮
│                                                            │
│  This operation requires administrator privileges.         │
│                                                            │
│  > Re-launch as Administrator (UAC prompt)                 │
│    Cancel                                                  │
│                                                            │
│  Note: This will restart the tool. Your current            │
│  navigation will be preserved.                             │
╰────────────────────────────────────────────────────────────╯
```

On confirm:
1. Build `RelaunchArgs` from current `AppState` navigation
2. Call `auth::relaunch_elevated(args)`
3. ShellExecuteW spawns new elevated process with hidden `--certmgr-*` resume args
4. Current process exits

On the new process:
1. `main.rs` detects `--certmgr` flag
2. Calls `launch_certmgr(Some(resume_args))` instead of the interactive menu
3. `launch_certmgr` pushes screens matching the safe resume args onto the nav stack
4. User lands at the same navigation target (location/store/physical view and selected cert when available), now elevated

Sensitive transient state is not resumed:
- Password fields
- Arbitrary file paths typed into dialogs
- Partially completed confirmation prompts

If the resumed location/store/path contains multiple matching certificates for the
saved selection hint, the tool resumes at the containing store view and shows a
status message instead of guessing which duplicate item to open.

### 13.4 User impersonation flow

```
╭─ User Store Access ───────────────────────────────────────╮
│                                                            │
│  Enter credentials to access another user's certificate    │
│  store.                                                    │
│                                                            │
│  Domain\Username : CORP\jdoe                               │
│  Password        : ********                                │
│                                                            │
│  [Enter] authenticate  [Esc] cancel                        │
╰────────────────────────────────────────────────────────────╯
```

On confirm:
1. Parse `DOMAIN\username` into domain and username parts
2. Call `auth::impersonate_user(username, domain, password)`
3. If successful: store `ImpersonationContext` in `AppState`, proceed to StoreListScreen
4. If failed: show error dialog with Win32 error and actionable message

Impersonation is reverted when:
- The user navigates back past the LocationScreen
- The user quits the cert manager
- `ImpersonationContext` is dropped (via `RevertToSelf` in `Drop` impl)

### 13.5 Service store access flow

```
╭─ Service Store Access ────────────────────────────────────╮
│                                                            │
│  Enter the Windows service name whose certificate store    │
│  you want to access.                                       │
│                                                            │
│  Service name : > IIS                                      │
│                                                            │
│  Note: Most service stores require administrator           │
│  privileges to access.                                     │
│                                                            │
│  [Enter] open  [Esc] cancel                                │
╰────────────────────────────────────────────────────────────╯
```

### 13.6 Graceful error dialogs

Every authentication/permission error shows a non-blocking dialog with three components:

```
╭─ Access Denied ───────────────────────────────────────────╮
│                                                            │
│  Could not access Local Machine > Personal (MY)            │
│  for import operation.                                     │
│                                                            │
│  Error  : 0x80070005 - Access is denied                    │
│                                                            │
│  To resolve:                                               │
│  • Run the tool as Administrator, or                       │
│  • Check that your account has write access to             │
│    the certificate store                                   │
│                                                            │
│  [Enter] ok                                                │
╰────────────────────────────────────────────────────────────╯
```

After dismissing, the user returns to the previous screen. Never a dead end.

---

## 14. Dependencies & Conditional Compilation

### 14.1 Workspace Cargo.toml additions

```toml
[workspace.dependencies]
# ... existing deps ...

# TUI framework (cross-platform -- will be reused for macOS Keychain, Linux trust stores)
ratatui = "0.29"
crossterm = "0.28"

# Windows certificate store support
schannel = "0.1"
x509-parser = "0.18"
windows-sys = { version = "0.61", features = [
    "Win32_Security_Cryptography",      # CertOpenStore, CertEnumSystemStore, CertEnumPhysicalStore,
                                        # CertAddCertificateContextToStore, CertDeleteCertificateFromStore,
                                        # CertCreateCertificateContext, CertGetCertificateContextProperty,
                                        # CertFreeCertificateContext, NCryptExportKey, CryptExportKey,
                                        # PFXExportCertStore
    "Win32_Security",                   # LogonUserW, ImpersonateLoggedOnUser, RevertToSelf
    "Win32_UI_Shell",                   # ShellExecuteW (UAC re-launch), IsUserAnAdmin
    "Win32_Foundation",                 # BOOL, HANDLE, GetLastError, CloseHandle, FormatMessageW
    "Win32_System_Threading",           # OpenProcessToken, GetCurrentProcess
] }

# Date handling for cert validity computation
chrono = { version = "0.4", default-features = false, features = ["std"] }
```

### 14.2 ssl-toolbox-win-certstore/Cargo.toml

```toml
[package]
name = "ssl-toolbox-win-certstore"
version.workspace = true
edition.workspace = true

# Only builds on Windows
[target.'cfg(windows)'.dependencies]
anyhow.workspace = true
schannel.workspace = true
x509-parser.workspace = true
windows-sys.workspace = true
serde.workspace = true
chrono.workspace = true

[dependencies]
# Cross-platform deps that are always needed for the type definitions
anyhow.workspace = true
serde.workspace = true
chrono.workspace = true
```

### 14.3 ssl-toolbox (binary) Cargo.toml additions

```toml
[dependencies]
# ... existing deps ...
ratatui.workspace = true
crossterm.workspace = true

[target.'cfg(windows)'.dependencies]
ssl-toolbox-win-certstore = { path = "../ssl-toolbox-win-certstore" }
```

### 14.4 Workspace members update

```toml
[workspace]
members = [
    "crates/ssl-toolbox",
    "crates/ssl-toolbox-core",
    "crates/ssl-toolbox-ca",
    "crates/ssl-toolbox-ca-sectigo",
    "crates/ssl-toolbox-win-certstore",  # NEW
]
```

### 14.5 Conditional compilation in binary crate

```rust
// crates/ssl-toolbox/src/main.rs

#[cfg(target_os = "windows")]
mod win_certmgr;

// In the Cli struct, add certmgr flag for UAC resume:
#[derive(Parser)]
struct Cli {
    #[arg(long, global = true)]
    debug: bool,

    /// Launch directly into Windows Certificate Manager (used for UAC resume)
    #[cfg(target_os = "windows")]
    #[arg(long, hide = true)]
    certmgr: bool,

    /// Resume location after UAC elevation
    #[cfg(target_os = "windows")]
    #[arg(long, hide = true)]
    certmgr_location: Option<String>,

    /// Resume store after UAC elevation
    #[cfg(target_os = "windows")]
    #[arg(long, hide = true)]
    certmgr_store: Option<String>,

    /// Resume physical/logical mode after UAC elevation
    #[cfg(target_os = "windows")]
    #[arg(long, hide = true, default_value_t = false)]
    certmgr_physical_view: bool,

    /// Resume physical store after UAC elevation
    #[cfg(target_os = "windows")]
    #[arg(long, hide = true)]
    certmgr_physical: Option<String>,

    /// Resume selected certificate after UAC elevation
    #[cfg(target_os = "windows")]
    #[arg(long, hide = true)]
    certmgr_thumbprint: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

// In main():
#[cfg(target_os = "windows")]
if cli.certmgr {
    let resume = win_certmgr::ResumeArgs {
        location: cli.certmgr_location,
        store: cli.certmgr_store,
        viewing_physical: cli.certmgr_physical_view,
        physical: cli.certmgr_physical,
        thumbprint: cli.certmgr_thumbprint,
    };
    return win_certmgr::launch_certmgr(Some(resume));
}

// In run_interactive_menu(), add menu item:
fn run_interactive_menu(debug: bool) -> Result<()> {
    // ... existing menu setup ...

    #[cfg(target_os = "windows")]
    {
        menu = menu.item(
            20,
            "Windows Certificate Manager",
            "Browse and manage Windows certificate stores",
        );
    }

    // ... existing menu items ...

    // In the match:
    #[cfg(target_os = "windows")]
    20 => {
        // cliclack uses the terminal in raw mode, ratatui needs to take over.
        // outro() cleanly exits the cliclack prompt context.
        win_certmgr::launch_certmgr(None)?;
        // After ratatui returns, re-display cliclack intro
        intro("SSL/TLS Security Toolbox")?;
    }
}
```

### 14.6 Build matrix impact

| Target | ratatui/crossterm | ssl-toolbox-win-certstore | schannel/windows-sys/x509-parser |
|--------|-------------------|--------------------------|----------------------------------|
| Linux x86_64 | Compiled (ready for future Linux trust store feature) | Not compiled | Not compiled |
| Linux aarch64 | Compiled | Not compiled | Not compiled |
| macOS x86_64 | Compiled (ready for future macOS Keychain feature) | Not compiled | Not compiled |
| macOS aarch64 | Compiled | Not compiled | Not compiled |
| Windows x86_64 | Compiled | Compiled | Compiled |

---

## 15. Event Loop & Screen Trait

### 15.1 Entry point

```rust
// win_certmgr/mod.rs

pub struct ResumeArgs {
    pub location: Option<String>,
    pub store: Option<String>,
    pub viewing_physical: bool,
    pub physical: Option<String>,
    pub thumbprint: Option<String>,
}

pub fn launch_certmgr(resume: Option<ResumeArgs>) -> anyhow::Result<()> {
    // Initialize terminal for ratatui
    let mut terminal = ratatui::init();
    terminal.clear()?;

    let mut app = AppState::new();

    // If resuming from UAC re-launch, push screens to match saved state
    if let Some(args) = resume {
        app.resume_navigation(&args)?;
    }

    // Main event loop
    loop {
        // Render current screen
        terminal.draw(|frame| {
            let area = frame.area();
            app.render(frame, area);
        })?;

        // Handle input events
        // Use poll with 250ms timeout to allow status message expiry
        if crossterm::event::poll(std::time::Duration::from_millis(250))? {
            match crossterm::event::read()? {
                crossterm::event::Event::Key(key) => {
                    // Ignore key release events (Windows generates these)
                    if key.kind == crossterm::event::KeyEventKind::Press {
                        match app.handle_key(key)? {
                            Action::Quit => break,
                            Action::Relaunch(args) => {
                                ratatui::restore();
                                ssl_toolbox_win_certstore::auth::relaunch_elevated(&args)?;
                                // If relaunch succeeds, this process should exit
                                std::process::exit(0);
                            }
                            _ => {}
                        }
                    }
                }
                crossterm::event::Event::Resize(w, h) => {
                    app.terminal_size = (w, h);
                    app.recalculate_page_size();
                }
                _ => {}
            }
        }

        // Expire status messages after 3 seconds
        app.expire_status_message();
    }

    // Restore terminal for cliclack
    ratatui::restore();
    Ok(())
}
```

### 15.1.1 Terminal cleanup guarantees

The ratatui/cliclack handoff must restore the terminal on every exit path:
- Normal quit back to the cliclack menu
- UAC relaunch before process exit
- Early return from initialization or event-loop errors
- Panic during rendering or input handling

Implementation should use a small RAII guard (and, if needed, a panic hook) so
`ratatui::restore()` is not dependent on a single success-path return.

### 15.2 Screen trait

```rust
// win_certmgr/app.rs

pub trait Screen {
    /// Render this screen's content into the given area.
    /// The breadcrumb bar and status bar are rendered by AppState, not the screen.
    fn render(&self, frame: &mut ratatui::Frame, area: ratatui::layout::Rect, state: &AppState);

    /// Handle a key event. Return an Action describing what happened.
    fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> anyhow::Result<Action>;

    /// The label for this screen in the breadcrumb bar.
    fn breadcrumb_label(&self) -> &str;

    /// Called when this screen becomes the active screen (pushed or returned to).
    /// Use for data loading (e.g., enumerate certs when entering a store).
    fn on_enter(&mut self, state: &mut AppState) -> anyhow::Result<()> {
        let _ = state;
        Ok(())
    }

    /// Called when this screen is about to be left (popped or another screen pushed on top).
    fn on_leave(&mut self, state: &mut AppState) -> anyhow::Result<()> {
        let _ = state;
        Ok(())
    }
}
```

### 15.3 Action enum

```rust
#[derive(Debug)]
pub enum Action {
    /// Nothing happened.
    None,
    /// Push a new screen onto the navigation stack.
    Push(Box<dyn Screen>),
    /// Pop the current screen (go back).
    Pop,
    /// Quit the cert manager entirely (return to cliclack).
    Quit,
    /// Refresh the current screen's data (re-enumerate certs, etc.).
    Refresh,
    /// Re-launch the process elevated with these args.
    Relaunch(RelaunchArgs),
    /// Show a modal dialog.
    ShowDialog(DialogState),
    /// Dismiss the current modal dialog.
    DismissDialog,
}
```

### 15.4 AppState rendering flow

```rust
impl AppState {
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        // Layout: breadcrumb (1 line) | main content | status bar (1 line)
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),   // breadcrumb
                Constraint::Min(1),      // main content
                Constraint::Length(1),   // status bar
            ])
            .split(area);

        // Render breadcrumb
        self.render_breadcrumb(frame, chunks[0]);

        // Render active screen
        if let Some(screen) = self.nav_stack.last() {
            screen.render(frame, chunks[1], self);
        }

        // Render status bar
        self.render_status_bar(frame, chunks[2]);

        // Render modal dialog on top if active
        if let Some(ref dialog) = self.active_dialog {
            self.render_dialog(frame, dialog, area);
        }
    }
}
```

---

## 16. TUI Widget Specifications

### 16.1 Breadcrumb widget (`widgets/breadcrumb.rs`)

Renders as a single line with:
- Left-aligned: `Windows Cert Manager` + `[elevation]` + ` > ` + screen labels
- Truncation: if the breadcrumb exceeds terminal width, truncate middle screens with `...`
- Styling: dim gray for separators, white for labels, yellow for `[User Mode]`, green for `[Administrator]`

### 16.2 Certificate table (`widgets/cert_table.rs`)

A `ratatui::widgets::Table` with:
- Header row with column names (styled bold)
- Data rows from `filtered_indices[page_start..page_end]`
- Selected row highlighted with reverse video
- Status column colored per status
- Key column shows `K` in green when present

### 16.3 Search bar (`widgets/search_bar.rs`)

Renders below the breadcrumb when in Search input mode:
- Shows `Search: ` prefix + the current query string + cursor
- In Normal mode, shows `Search: {query}` if a query is active, or nothing if empty

### 16.4 Status bar (`widgets/status_bar.rs`)

Single line at the bottom:
- Left side: pagination info (`Page 1/12 | 294 total | 47 shown`)
- Center: sort info (`Sort: Subject ↑`)
- Right side: key hints (`[i]mport [e]xport [/]search [?]help`)
- Temporary status messages (e.g., "Exported to...") replace the center section for 3 seconds

### 16.5 Dialog widget (`widgets/dialog.rs`)

Renders a centered modal box:
- Fixed percentage of terminal (60% width, up to 80% height)
- Border with title
- Scrollable content area
- Action buttons at the bottom
- Background is dimmed (render a semi-transparent Block over the main content)

### 16.6 File input widget (`widgets/file_input.rs`)

Text input with:
- Current path display
- Tab-completion: pressing Tab cycles through matching files/dirs in the current directory
- Enter: accept the current path
- Esc: cancel

---

## 17. CLI Subcommand Integration

In addition to the interactive TUI, expose cert store operations as direct CLI subcommands for scripting and automation.

### 17.1 New subcommands

```rust
#[derive(Subcommand)]
enum Commands {
    // ... existing commands ...

    /// Windows Certificate Manager operations
    #[cfg(target_os = "windows")]
    #[command(subcommand)]
    CertStore(CertStoreCommands),
}

#[cfg(target_os = "windows")]
#[derive(Subcommand)]
enum CertStoreCommands {
    /// List certificates in a store
    List {
        /// Store location: current-user, local-machine
        #[arg(short, long, default_value = "current-user")]
        location: String,
        /// Store name (e.g., MY, Root, CA)
        #[arg(short, long, default_value = "MY")]
        store: String,
        /// Output format: table, json
        #[arg(short, long, default_value = "table")]
        format: String,
    },
    /// Show certificate details
    Show {
        #[arg(short, long)]
        location: String,
        #[arg(short, long)]
        store: String,
        /// Thumbprint (SHA-1) of the certificate to show
        #[arg(short, long)]
        thumbprint: String,
    },
    /// Import a certificate into a store
    Import {
        #[arg(short, long)]
        location: String,
        #[arg(short, long)]
        store: String,
        /// Path to certificate file
        #[arg(short, long)]
        file: String,
        /// Password (for PFX files)
        #[arg(short, long)]
        password: Option<String>,
        /// Mark imported private keys as exportable (PFX only)
        #[arg(long)]
        exportable: bool,
    },
    /// Export a certificate from a store
    Export {
        #[arg(short, long)]
        location: String,
        #[arg(short, long)]
        store: String,
        #[arg(short, long)]
        thumbprint: String,
        /// Output path
        #[arg(short, long)]
        out: String,
        /// Export format: pem, der, pfx, p7b, base64
        #[arg(short, long)]
        format: String,
        /// PFX export password
        #[arg(long)]
        pfx_password: Option<String>,
        /// Include chain certificates
        #[arg(long)]
        chain: bool,
    },
    /// Delete a certificate from a store
    Delete {
        #[arg(short, long)]
        location: String,
        #[arg(short, long)]
        store: String,
        #[arg(short, long)]
        thumbprint: String,
        /// Skip confirmation (for scripts)
        #[arg(long)]
        force: bool,
    },
    /// List available store names at a location
    Stores {
        #[arg(short, long, default_value = "current-user")]
        location: String,
    },
    /// Launch the interactive TUI certificate manager
    Browse,
}
```

---

## 18. Integration with ssl-toolbox-core

### 18.1 Reuse points

| ssl-toolbox-core module | Reuse in win-certstore | How |
|------------------------|----------------------|-----|
| `convert::detect_format()` | Extended for PKCS7 | Call existing function, add PEM/DER PKCS7 recognition before generic PEM/PKCS12 checks |
| `CertFormat` enum | Extended | Add `Pkcs7` variant to the existing enum in cert_types.rs |
| `CertDetails` struct | Display integration | Convert `CertEntry` to `CertDetails` for compatibility with existing display functions |
| `pfx::extract_pfx_details()` | Import preview | Use for PFX preview before import |
| `x509_utils::extract_sans()` | Parsing | Not directly reused (x509-parser has its own SAN extraction), but the format is compatible |

### 18.2 Changes to ssl-toolbox-core

**cert_types.rs** -- Add PKCS7 variant to CertFormat:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertFormat {
    Pem,
    Der,
    Pkcs12,
    Pkcs7,    // NEW
    Base64,
    Unknown,
}
```

**convert.rs** -- Add PKCS7 detection to `detect_format()`:

```rust
pub fn detect_format(data: &[u8]) -> CertFormat {
    // NEW: Check for PEM-encoded PKCS7 before generic PEM.
    if is_pkcs7_pem(data) {
        return CertFormat::Pkcs7;
    }

    // Check for PEM markers
    if let Ok(text) = std::str::from_utf8(data)
        && text.contains("-----BEGIN ")
    {
        return CertFormat::Pem;
    }

    // NEW: Check for DER PKCS7 before PKCS12 (both are ASN.1, but PKCS7 has specific OID)
    if is_pkcs7_der(data) {
        return CertFormat::Pkcs7;
    }

    // Try PKCS12
    if Pkcs12::from_der(data).is_ok() {
        return CertFormat::Pkcs12;
    }

    // ... rest unchanged ...
}

fn is_pkcs7_pem(data: &[u8]) -> bool {
    std::str::from_utf8(data)
        .map(|text| text.contains("-----BEGIN PKCS7-----"))
        .unwrap_or(false)
}

fn is_pkcs7_der(data: &[u8]) -> bool {
    // PKCS7 signedData OID: 1.2.840.113549.1.7.2
    // DER-encoded: 06 09 2A 86 48 86 F7 0D 01 07 02
    let oid = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
    data.len() > 30 && data[..std::cmp::min(data.len(), 30)].windows(oid.len()).any(|w| w == oid)
}
```

**convert.rs** -- Add format_description for PKCS7:

```rust
pub fn format_description(format: CertFormat) -> &'static str {
    match format {
        // ... existing ...
        CertFormat::Pkcs7 => "PKCS#7 / P7B (certificate chain bundle)",
    }
}
```

### 18.3 Conversion between CertEntry and CertDetails

The win-certstore crate can produce a `CertDetails` from a `CertEntry` for compatibility:

```rust
impl CertEntry {
    pub fn to_core_cert_details(&self) -> ssl_toolbox_core::CertDetails {
        ssl_toolbox_core::CertDetails {
            common_name: self.subject_cn.clone(),
            sans: self.sans.iter().map(|s| s.to_display_string()).collect(),
            not_before: self.not_before.to_string(),
            not_after: self.not_after.to_string(),
            issuer: self.issuer_cn.clone(),
        }
    }
}
```

---

## 19. Performance & Caching

### 19.1 Lazy loading

Certificates are loaded only when a store is opened (on `StoreViewScreen::on_enter()`). Navigation to LocationScreen and StoreListScreen does not trigger any certificate enumeration.

### 19.2 Certificate parsing strategy

When enumerating a store:
1. Call `store.certs()` to get all `CertContext` handles
2. For each cert: duplicate the `PCCERT_CONTEXT` into a `CertHandle`
3. Extract DER bytes, parse with `x509-parser`, detect private-key presence from certificate properties
4. Build `CertEntry` structs with all pre-parsed fields
5. This happens once per store open. The `certs: Vec<CertEntry>` is then used for all rendering.

Estimated cost for a store with 300 certificates: ~50-150ms total parse time.
The design avoids opening key providers during list enumeration, so smart-card and
HSM-backed certificates do not stall the main table load.

### 19.3 Refresh behavior

The `r` key triggers a full re-enumeration of the current store. This discards the cached `certs` vector and rebuilds it from scratch. The sort/filter state is preserved but re-applied to the new data.

### 19.4 No background loading

All store operations are synchronous and blocking. Given the small data volumes (even large stores have <1000 certs) and fast Win32 APIs, there's no need for background threads or async loading. The TUI event loop blocks briefly during store enumeration -- this is acceptable.

### 19.5 Memory

Each `CertEntry` holds its full DER bytes (typically 1-3 KB per cert). For a store with 300 certs, this is ~300 KB-1 MB. Negligible.

---

## 20. Edge Cases

### 20.1 Empty stores

If a store contains no certificates, `StoreViewScreen` shows a centered message:
```
No certificates found in this store.
Press [i] to import, or [Esc] to go back.
```

### 20.2 Smart card certificates

Smart card certs appear in the store enumeration like any other cert. Presence
detection uses certificate properties only, so list rendering does not prompt for
a PIN. Lazy metadata load or explicit `k` inspection may fail or require user
interaction; in that case the UI shows the key as present but its details as unavailable.

### 20.3 Hardware Security Module (HSM) keys

Similar to smart cards: the certificate is in the store but the private key is in
the HSM. Key detection returns `Present`; lazy metadata load may reveal the HSM
provider name, and key inspection returns `Unavailable` since HSM keys are never exportable.

### 20.4 Corrupted or unparseable certificates

If `x509_parser::parse_x509_certificate()` fails for a cert:
- The cert is still included in the list
- `subject_cn` is set to `"<parse error>"`
- `issuer_cn` is set to `"<parse error>"`
- Other fields are set to defaults
- The DER bytes are preserved for export/delete operations
- The detail view shows a warning: "This certificate could not be fully parsed."

### 20.5 Very long SANs or DN fields

Some certificates have hundreds of SANs (e.g., CDN certs). The detail view handles this with scrolling. The table view only shows the subject CN, not individual SANs.

### 20.6 Self-signed certificates

Self-signed certs (issuer == subject) are displayed normally. The detail view notes "Self-signed" in the issuer section.

### 20.7 Expired root CAs

Root CAs in the `Root` store may be expired. They are shown with `Expired` status. Delete requires the same thumbprint confirmation -- no special treatment.

### 20.8 Store open failure

If a store cannot be opened (permissions, nonexistent, etc.), show an error dialog and return to the previous screen. Do not crash.

### 20.9 Concurrent store modification

If another process adds or removes certificates while the TUI is open, the cached list becomes stale. The user can press `r` to refresh. No automatic polling.

### 20.10 Terminal too small

If the terminal is narrower than 80 columns or shorter than 15 rows, show a message:
```
Terminal too small. Minimum: 80x15.
Current: {w}x{h}
```
Resume normal rendering when the terminal is resized above the minimum.

---

## 21. Testing Strategy

### 21.1 Unit tests (cross-platform)

The following can be tested on any platform (no Windows APIs needed):

- `cert.rs`: `thumbprint_sha1()`, `thumbprint_sha256()`, `compute_status()`, `parse_distinguished_name()`, `extract_public_key_info()` -- feed known DER bytes, verify parsed fields.
- `types.rs`: `CertStatus` computation, `San` display formatting, `DistinguishedName` formatting.
- `error.rs`: Error display formatting.
- Format detection: `detect_import_format()` with sample files of each format,
  including PEM-encoded PKCS7 and unsupported inputs returning `None`.
- Filter logic: `AppState::matches_filter()`, `AppState::compare_certs()`.

### 21.2 Integration tests (Windows-only)

Gated behind `#[cfg(test)]` + `#[cfg(target_os = "windows")]`:

- **Store enumeration**: Open `CurrentUser\MY` and `CurrentUser\Root`, verify certs are returned.
- **Physical store listing**: List physical stores for `CurrentUser\Root`, verify `.Default` exists.
- **Import/export round-trip**: Import a test PFX into a temporary store name, export it back, verify the cert matches.
- **Private key detection**: Import a PFX with a private key, verify `PrivateKeyStatus::Present` is returned without forcing provider acquisition during list enumeration.
- **Resume behavior**: Verify hidden `--certmgr-*` args restore logical view, physical view, and selected certificate when available.
- **Elevation check**: Verify `check_elevation()` returns a valid `ElevationStatus`.

### 21.3 Test certificates

Include test certificate files in `crates/ssl-toolbox-win-certstore/tests/fixtures/`:
- `test.pem` -- self-signed PEM cert
- `test.der` -- same cert in DER format
- `test.pfx` -- cert + key in PFX (password: "test")
- `test-chain.p7b` -- PKCS7 bundle with leaf + intermediate + root
- `test-expired.pem` -- expired certificate for status testing
- `test-not-yet-valid.pem` -- cert with future not_before

### 21.4 TUI testing

Manual testing protocol:
1. Build on Windows: `cargo build --target x86_64-pc-windows-msvc`
2. Run: `ssl-toolbox` and select "Windows Certificate Manager"
3. Verify: navigation, breadcrumbs, cert listing, search, filter, sort, pagination
4. Test import/export with each format
5. Test delete with thumbprint confirmation
6. Test elevation flow: run as normal user, attempt LocalMachine import
7. Test UAC re-launch and navigation resume
8. Test terminal resize at every screen

---

## 22. Windows Certificate Store Reference

### 22.1 Standard store names

| Store Name | Display Name | Description |
|------------|-------------|-------------|
| MY | Personal | Certificates with associated private keys |
| Root | Trusted Root CAs | Trusted root CA certificates |
| CA | Intermediate CAs | Intermediate and subordinate CA certificates |
| Trust | Enterprise Trust | Certificate trust lists (CTLs) |
| Disallowed | Untrusted Certificates | Explicitly untrusted or revoked certificates |
| TrustedPeople | Trusted People | Certificates of explicitly trusted people or endpoints |
| TrustedPublisher | Trusted Publishers | Certificates of trusted software publishers |
| AuthRoot | Third-Party Root CAs | Third-party root CAs (auto-updated by Microsoft) |
| SmartCardRoot | Smart Card Trusted Roots | Smart card root CA certificates |
| UserDS | Active Directory User Object | Certificates published to Active Directory (CurrentUser only) |

### 22.2 Store locations and flags

| Location | Flag Constant | Value | Description | Write Elevation |
|----------|--------------|-------|-------------|-----------------|
| Current User | CERT_SYSTEM_STORE_CURRENT_USER | 0x00010000 | Per-user certificates | No |
| Local Machine | CERT_SYSTEM_STORE_LOCAL_MACHINE | 0x00020000 | Machine-wide certificates | Yes |
| Current Service | CERT_SYSTEM_STORE_CURRENT_SERVICE | 0x00040000 | Service process certificates | Depends |
| Services | CERT_SYSTEM_STORE_SERVICES | 0x00050000 | Named service certificates | Yes |
| Users | CERT_SYSTEM_STORE_USERS | 0x00060000 | Named user certificates | Yes + impersonation |
| GP User | CERT_SYSTEM_CURRENT_USER_GROUP_POLICY | 0x00070000 | User Group Policy certificates | Read-only |
| GP Machine | CERT_SYSTEM_LOCAL_MACHINE_GROUP_POLICY | 0x00080000 | Machine Group Policy certificates | Read-only |
| Enterprise | CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE | 0x00090000 | Enterprise certificates from AD | Read-only |

### 22.3 Physical store composition

| Logical Store (CurrentUser) | Physical Stores |
|---------------------------|-----------------|
| Root | .Default, .GroupPolicy, .LocalMachine, .SmartCard |
| CA | .Default, .GroupPolicy, .LocalMachine |
| MY | .Default, .SmartCard |
| Trust | .Default, .GroupPolicy |
| Disallowed | .Default, .GroupPolicy |

| Logical Store (LocalMachine) | Physical Stores |
|----------------------------|-----------------|
| Root | .Default, .AuthRoot, .GroupPolicy, .Enterprise, .SmartCard |
| CA | .Default, .GroupPolicy |
| MY | .Default |
| Trust | .Default, .GroupPolicy, .Enterprise |

### 22.4 Private key providers

| Provider Type | Provider Name | Key Location |
|-------------|--------------|-------------|
| CNG (modern) | Microsoft Software Key Storage Provider | `%APPDATA%\Microsoft\Crypto\Keys` (user) or `%ProgramData%\Microsoft\Crypto\Keys` (machine) |
| CNG (TPM) | Microsoft Platform Crypto Provider | Hardware TPM |
| CNG (smart card) | Microsoft Smart Card Key Storage Provider | Smart card hardware |
| CryptoAPI (legacy) | Microsoft Enhanced RSA and AES Cryptographic Provider | `%APPDATA%\Microsoft\Crypto\RSA` |
| CryptoAPI (legacy) | Microsoft Base Cryptographic Provider v1.0 | Same as above |

### 22.5 Key exportability

- Set at import time via `CRYPT_EXPORTABLE` flag in `PFXImportCertStore`
- Non-exportable keys: `NCryptExportKey` returns `NTE_NOT_SUPPORTED` (0x80090029)
- Cannot be changed after import -- must re-import with the flag
- Machine key ACLs also apply: even exportable machine keys require admin to export

### 22.6 Well-known Extended Key Usage OIDs

| OID | Name |
|-----|------|
| 1.3.6.1.5.5.7.3.1 | Server Authentication |
| 1.3.6.1.5.5.7.3.2 | Client Authentication |
| 1.3.6.1.5.5.7.3.3 | Code Signing |
| 1.3.6.1.5.5.7.3.4 | Secure Email (S/MIME) |
| 1.3.6.1.5.5.7.3.8 | Time Stamping |
| 1.3.6.1.5.5.7.3.9 | OCSP Signing |
| 1.3.6.1.4.1.311.10.3.1 | Microsoft Trust List Signing |
| 1.3.6.1.4.1.311.10.3.4 | Microsoft Encrypted File System |
| 1.3.6.1.4.1.311.20.2.2 | Microsoft Smart Card Logon |

---

## 23. Key Technology Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Store operations | schannel + windows-sys | schannel for ergonomic Rust API covering 80% of operations. windows-sys fills the gaps: physical store enumeration, system store enumeration, service/user store access, private key parameter extraction, authentication APIs. |
| Certificate parsing | x509-parser v0.18 | Mature, zero-copy nom parser with full extension support (SAN, KU, EKU, basic constraints). Complements schannel's raw DER output. Preferred over x509-cert because it's more ergonomic for read-only display. |
| TUI framework | ratatui v0.29 + crossterm v0.28 | Industry standard Rust TUI stack. Supports tables, scrolling, overlays, input handling, resize. crossterm provides cross-platform terminal control. |
| Date handling | chrono v0.4 | Needed for computing "days remaining" and "expiring soon" from x509-parser's ASN1Time values. |
| Coexistence with cliclack | Alternate screen handoff | launch_certmgr() enters ratatui alternate screen. ratatui::restore() cleans up before returning to the cliclack main loop. No conflict between the two frameworks. |
| WinRT Certificate API | Rejected | Requires async runtime (tokio), WinRT activation context, and does not cleanly distinguish CurrentUser vs LocalMachine stores. The rich property access (direct `.Subject()`, `.Issuer()`) doesn't justify the complexity since x509-parser provides the same fields synchronously. |
| Crate isolation | Separate ssl-toolbox-win-certstore | Keeps Windows-specific unsafe code and large dependency tree (windows-sys) isolated from ssl-toolbox-core. Clean compilation boundary. The library crate can be tested independently. |
| Format detection | Extend ssl-toolbox-core | Add Pkcs7 variant to existing CertFormat enum and PKCS7 detection to existing detect_format(). Keeps format logic centralized. |
| Error handling | Custom WinCertError enum | Wraps Win32 error codes with function context and actionable messages. Converts cleanly to anyhow::Error at the TUI boundary. |
| Private key approach | Detect presence by default, load metadata and inspect on request | Store enumeration uses certificate properties only. Provider metadata loads lazily in detail view. Parameter extraction requires exportable keys and is a privileged operation gated behind explicit user action. |
| Physical stores | windows-sys CertEnumPhysicalStore | schannel doesn't expose physical store enumeration. Drop down to Win32 callback API for this specific feature. Wrap the unsafe callback in a safe Rust iterator. |
| Navigation state resume | CLI args | When re-launching elevated via ShellExecuteW, encode safe navigation state as hidden `--certmgr-*` args, including physical-view state and selected thumbprint when available. Sensitive dialog input is intentionally not resumed. |

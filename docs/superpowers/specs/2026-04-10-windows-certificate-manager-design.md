# Windows Certificate Manager Integration

**Date:** 2026-04-10
**Status:** Approved
**Approach:** Approach A -- ratatui TUI for cert manager, cliclack retained for existing features

---

## Overview

Add a Windows Certificate Manager feature to SSL-Toolbox that provides full interactive access to the Windows certificate stores. The feature launches as a ratatui-based TUI from the existing cliclack main menu, offering tree-style navigation through store locations, store names, physical stores, and individual certificates. Supports viewing public/private keys, importing and exporting in all standard formats, and authentication/elevation for privileged operations.

---

## 1. Crate Architecture

### New crate: `ssl-toolbox-win-certstore`

A Windows-only library crate providing certificate store operations with no UI dependency.

```
crates/ssl-toolbox-win-certstore/
  Cargo.toml
  src/
    lib.rs              -- Public API surface
    store.rs            -- Store enumeration, open, physical store discovery
    cert.rs             -- Certificate reading, parsing, property extraction
    private_key.rs      -- Private key detection, inspection, export
    import.rs           -- Import operations (PFX, PEM, DER, PKCS7, Base64)
    export.rs           -- Export operations (same formats)
    auth.rs             -- Elevation detection, UAC re-launch, user impersonation
    error.rs            -- Windows-specific error types
```

The entire crate compiles only on Windows. The binary crate depends on it behind `cfg(windows)`.

### TUI layer in binary crate: `src/win_certmgr/`

Presentation logic using ratatui, gated behind `#[cfg(target_os = "windows")]`.

```
crates/ssl-toolbox/src/win_certmgr/
  mod.rs              -- Entry point: launch_certmgr()
  app.rs              -- AppState, navigation stack, event loop
  screens/
    mod.rs
    location.rs       -- Store location select
    store_list.rs     -- Store name select
    store_view.rs     -- Paginated cert list with search/filter/sort
    physical.rs       -- Physical store list and browsing
    cert_detail.rs    -- Full certificate detail view
    key_inspect.rs    -- Private key inspection overlay
  widgets/
    mod.rs
    breadcrumb.rs     -- Breadcrumb bar widget
    cert_table.rs     -- Paginated, sortable cert table
    search_bar.rs     -- Search/filter input
    status_bar.rs     -- Footer with page info, elevation status
    dialog.rs         -- Confirmation dialogs, import preview, auth prompts
  actions/
    mod.rs
    import.rs         -- Import flow orchestration
    export.rs         -- Export flow orchestration
    delete.rs         -- Delete flow with thumbprint confirmation
  theme.rs            -- Colors, borders, consistent styling
```

### Separation of concerns

- `ssl-toolbox-win-certstore` -- pure data operations, no UI, no terminal interaction. Returns `Result<T>`.
- `win_certmgr/screens/` -- maps data to ratatui widgets, handles input for each screen.
- `win_certmgr/actions/` -- multi-step flows spanning prompts and operations.
- `win_certmgr/widgets/` -- reusable ratatui components shared across screens.

---

## 2. Navigation & Screen Architecture

### Stack-based navigation

Each screen pushes onto a `nav_stack: Vec<Screen>`. "Back" (Esc/Backspace) pops. A breadcrumb bar at the top reflects the current position.

### Screen flow

```
Main Menu (cliclack)
  --> Windows Certificate Manager (ratatui takes over)
        |
        +-- Store Location Select
        |     +-- Current User
        |     +-- Local Machine
        |     +-- Service: [service name]
        |     +-- User: [username] (prompts for credentials)
        |
        +-- Store Select (for chosen location)
        |     +-- Personal (MY)
        |     +-- Trusted Root CAs (Root)
        |     +-- Intermediate CAs (CA)
        |     +-- Trusted People
        |     +-- Trusted Publishers
        |     +-- Enterprise Trust
        |     +-- Untrusted (Disallowed)
        |     +-- [dynamically discovered stores]
        |
        +-- Store View (logical) ---- [Tab toggle] ---- Physical Store List
        |     |                                           +-- .Default
        |     |                                           +-- .GroupPolicy
        |     |                                           +-- .LocalMachine
        |     |
        |     +-- Paginated cert list (25 per page)
        |     +-- Search/filter bar
        |     +-- Actions: [Import] [Export All] [Refresh]
        |
        +-- Certificate Detail View
              +-- Subject, Issuer, Serial, Thumbprint
              +-- Validity (Not Before / Not After)
              +-- SANs, Key Usage, Extended Key Usage
              +-- Public key info (algorithm, size, value)
              +-- Private key status (present/absent, provider, exportable)
              +-- Chain info
              +-- Actions: [Export] [Delete] [Inspect Private Key]
```

### Breadcrumb examples

```
Windows Cert Manager [User Mode] > Local Machine > Personal (MY)
Windows Cert Manager [Administrator] > Current User > Root > CN=DigiCert Global Root G2
```

### Key bindings

| Key | Action |
|-----|--------|
| Up/Down or j/k | Navigate list |
| Enter | Select / drill in |
| Esc or Backspace | Go back one level |
| / | Activate search |
| f | Open filter options |
| Tab | Toggle logical/physical view (Store View) |
| i | Import |
| e | Export |
| d | Delete |
| s | Cycle sort column |
| S | Reverse sort |
| n/p or Left/Right | Next/previous page |
| v | Expand truncated values (Detail View) |
| k | Inspect private key (Detail View) |
| q | Quit back to cliclack main menu |

### State model

```rust
struct AppState {
    nav_stack: Vec<Screen>,
    current_location: Option<StoreLocation>,
    current_store: Option<String>,
    viewing_physical: bool,
    current_physical: Option<String>,
    certs: Vec<CertEntry>,
    selected_index: usize,
    page: usize,
    search_query: String,
    filter: CertFilter,
    sort_column: SortColumn,
    sort_ascending: bool,
    elevation_status: ElevationStatus,
    impersonation: Option<ImpersonationContext>,
}
```

---

## 3. Certificate List & Filtering

### Table columns

```
 #  | Subject CN              | Issuer CN          | Expires     | Status  | Key | Thumbprint
----+-------------------------+--------------------+-------------+---------+-----+-----------
 1  | server.example.com      | DigiCert G2        | 2026-12-01  | Valid   | K   | A1B2C3...
 2  | *.internal.corp         | Internal CA        | 2025-01-15  | Expired | K   | D4E5F6...
 3  | DigiCert Global Root G2 | DigiCert Global R. | 2038-01-15  | Valid   |     | 7A8B9C...
```

- **Status**: `Valid`, `Expired`, `Not Yet Valid`, `Expiring Soon` (within 30 days)
- **Key column**: `K` indicator if private key present, empty if not
- Columns resize based on terminal width, CN fields truncate first

### Filter

```rust
struct CertFilter {
    text_query: Option<String>,      // matches subject, issuer, SAN, thumbprint
    status: Option<CertStatus>,      // Valid, Expired, ExpiringSoon, NotYetValid
    has_private_key: Option<bool>,
    key_usage: Option<Vec<String>>,  // Server Auth, Client Auth, Code Signing, etc.
}
```

### Pagination

- 25 certs per page default, adjusts to terminal height
- Footer: `Page 2/12 | 294 certificates | 3 filtered`
- Left/Right or n/p for page navigation
- Search applies across all pages, resets to page 1

### Sorting

- Default: subject CN ascending
- Cycle with `s`: Subject -> Issuer -> Expiry -> Status -> Thumbprint
- Reverse with `S`

---

## 4. Certificate Detail View

Full-screen scrollable view with sections:

- **Subject** -- full distinguished name (CN, O, OU, L, S, C)
- **Issuer** -- full distinguished name
- **Validity** -- Not Before, Not After, computed status with days remaining
- **Serial Number** -- colon-separated hex
- **Thumbprint** -- SHA-1 and SHA-256
- **Subject Alternative Names** -- DNS, IP, email, URI entries
- **Key Usage** -- Digital Signature, Key Encipherment, etc.
- **Extended Key Usage** -- OID name + numeric OID
- **Public Key** -- algorithm, bit size, modulus (truncated, `v` to expand), exponent
- **Private Key** -- present/absent, provider name (CNG vs CryptoAPI), exportable flag, container name
- **Signature** -- algorithm name + OID

### Private key inspection

Triggered by `k` from detail view. Shows confirmation prompt before accessing key material.

For exportable keys: displays full key parameters (modulus, exponent, primes P/Q).

For non-exportable keys: displays public parameters only with message: "Private key parameters not accessible (key is not marked exportable)".

### Actions from detail view

- `e` -- export this certificate
- `d` -- delete with thumbprint confirmation
- `k` -- inspect private key

---

## 5. Import & Export Operations

### Import flow

1. File path prompt (accepts: .pfx, .p12, .pem, .crt, .cer, .der, .p7b, .p7c, .b64)
2. Auto-detect format using existing `ssl-toolbox-core::convert::detect_format()` plus new PKCS7 detection
3. Format-specific prompts:
   - PFX/PKCS12: password prompt
   - PEM: detect multiple certs, ask "Import all N certificates?"
   - PKCS7: extract and show cert count
   - DER/Base64: single cert
4. Pre-import summary showing file, format, contents, target store, and cert CN/expiry
5. Elevation prompt if needed
6. Execute, show success/failure, refresh cert list

### Export flow

1. Scope: single cert (from detail view) or all certs (from store view)
2. Format selection menu:
   - PEM (.pem) -- Base64 encoded
   - DER (.der) -- Binary encoded
   - PFX/PKCS12 (.pfx) -- with private key
   - PKCS7/P7B (.p7b) -- certificate chain
   - Base64 (.b64) -- Base64 without PEM headers
3. Format-specific prompts:
   - PFX: "Include private key?" -> "Set export password". Warn if key not exportable.
   - PKCS7: "Include full chain?" -> attempt chain building
   - PEM: "Include chain certificates?"
4. Output path prompt with smart default (e.g., `~/CN_name.pfx`)
5. Elevation prompt if private key export on LocalMachine
6. Execute, show success with file path

### Delete flow

1. Confirmation dialog showing cert CN, store, and thumbprint
2. User must type first 8 hex characters of thumbprint to confirm
3. Elevation prompt if needed
4. Execute, show success, refresh cert list

---

## 6. Authentication & Elevation

### Elevation detection

On entering the cert manager, check `IsUserAnAdmin()` via `windows-sys`. Display status in breadcrumb bar:

```
Windows Cert Manager [User Mode] > ...
Windows Cert Manager [Administrator] > ...
```

### Scenario 1: UAC elevation for LocalMachine writes

Prompt: "This operation requires administrator privileges."
Options: "Re-launch as Administrator (UAC prompt)" or "Cancel"

Implementation: `ShellExecuteW` with `"runas"` verb. Pass CLI args encoding current navigation state (`--certmgr --location local-machine --store MY`) so re-launched process resumes at the same screen.

### Scenario 2: User impersonation for other user stores

Prompt for DOMAIN\username and password.

Implementation: `LogonUser` with `LOGON32_LOGON_INTERACTIVE` + `ImpersonateLoggedOnUser`. Context held in `AppState.impersonation`, reverted with `RevertToSelf` on navigate-away or exit.

### Scenario 3: Service store access

Prompt for service name. Requires admin -- triggers UAC flow first if not elevated.

Implementation: `CertOpenStore` with `CERT_SYSTEM_STORE_SERVICES` flag and `ServiceName\StoreName` parameter.

### Graceful fallback

All authentication failures show a non-blocking dialog with:
- What failed
- Windows error code (e.g., 0x80070005)
- How to resolve (run as admin, check ACLs)
- Returns to previous screen -- never a dead end

---

## 7. Dependencies & Conditional Compilation

### New workspace dependencies (root Cargo.toml)

```toml
[workspace.dependencies]
ratatui = "0.29"
crossterm = "0.28"
schannel = "0.1"
x509-parser = "0.18"
windows-sys = { version = "0.61", features = [
    "Win32_Security_Cryptography",
    "Win32_Security",
    "Win32_UI_Shell",
    "Win32_Foundation",
    "Win32_System_Threading",
] }
```

### ssl-toolbox-win-certstore/Cargo.toml

```toml
[package]
name = "ssl-toolbox-win-certstore"
edition.workspace = true

[dependencies]
anyhow.workspace = true
schannel.workspace = true
x509-parser.workspace = true
windows-sys.workspace = true
serde.workspace = true
```

All dependencies gated with `[target.'cfg(windows)'.dependencies]`.

### ssl-toolbox (binary) Cargo.toml additions

```toml
[dependencies]
ratatui.workspace = true
crossterm.workspace = true

[target.'cfg(windows)'.dependencies]
ssl-toolbox-win-certstore = { path = "../ssl-toolbox-win-certstore" }
```

### Conditional compilation

```rust
// src/main.rs
#[cfg(target_os = "windows")]
mod win_certmgr;

// Menu item only appears on Windows
#[cfg(target_os = "windows")]
menu_items.push(("Windows Certificate Manager", 20));
```

### Build matrix impact

- Linux/macOS: gain ratatui + crossterm as unconditional deps. These are intentionally cross-platform -- they will be reused when macOS Keychain and Linux trust store features are added. No Windows crate compiled.
- Windows: full feature set with all dependencies.

---

## 8. Event Loop & Screen Trait

### Entry point

```rust
pub fn launch_certmgr() -> anyhow::Result<()> {
    let mut terminal = ratatui::init();
    let mut app = AppState::new();

    loop {
        terminal.draw(|frame| app.render(frame))?;

        match crossterm::event::read()? {
            Event::Key(key) => {
                if app.handle_key(key)? == Action::Quit {
                    break;
                }
            }
            Event::Resize(w, h) => app.resize(w, h),
            _ => {}
        }
    }

    ratatui::restore();
    Ok(())
}
```

### Screen trait

```rust
trait Screen {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState);
    fn handle_key(&mut self, key: KeyEvent, state: &mut AppState) -> Result<Action>;
    fn breadcrumb_label(&self) -> &str;
}
```

Each screen implements this trait. The `AppState` renders the current top-of-stack screen and delegates key events to it.

### Action enum

```rust
enum Action {
    None,
    Push(Box<dyn Screen>),
    Pop,
    Quit,
    Refresh,
}
```

---

## 9. Windows Certificate Store Reference

### Standard store names

| Store Name | Display Name | Description |
|------------|-------------|-------------|
| MY | Personal | Certificates with private keys |
| Root | Trusted Root CAs | Trusted root CA certificates |
| CA | Intermediate CAs | Intermediate/subordinate CA certificates |
| Trust | Enterprise Trust | Certificate trust lists |
| Disallowed | Untrusted | Explicitly untrusted/revoked certs |
| TrustedPeople | Trusted People | Explicitly trusted endpoint certs |
| TrustedPublisher | Trusted Publishers | Trusted software publisher certs |
| AuthRoot | Third-Party Root CAs | Auto-updated third-party roots |

### Store locations

| Location | Flag | Description | Elevation for writes |
|----------|------|-------------|---------------------|
| Current User | CERT_SYSTEM_STORE_CURRENT_USER | Per-user certs | No |
| Local Machine | CERT_SYSTEM_STORE_LOCAL_MACHINE | Machine-wide certs | Yes |
| Service | CERT_SYSTEM_STORE_SERVICES | Named service certs | Yes |
| Users | CERT_SYSTEM_STORE_USERS | Named user certs | Yes (+ impersonation) |
| Current Service | CERT_SYSTEM_STORE_CURRENT_SERVICE | Calling service certs | Depends |
| Group Policy (User) | CERT_SYSTEM_CURRENT_USER_GROUP_POLICY | User GPO certs | Read-only |
| Group Policy (Machine) | CERT_SYSTEM_LOCAL_MACHINE_GROUP_POLICY | Machine GPO certs | Read-only |

### Physical vs logical stores

Each system store is a logical collection of physical sibling stores. For example, `CurrentUser\Root` merges `.Default` + `.LocalMachine` + `.GroupPolicy` + `.SmartCard`. The Tab toggle in Store View switches between the merged logical view and the individual physical stores.

### Private key providers

- **CNG (modern):** Microsoft Software Key Storage Provider. Keys managed by Key Storage Providers.
- **CryptoAPI (legacy):** Cryptographic Service Providers. Older key containers.
- `schannel` handles both via `PrivateKey::NcryptKey` and `PrivateKey::CryptProv`.
- Exportable flag set at import time. Non-exportable keys cannot have their parameters read.

---

## 10. Key Technology Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Store operations | schannel + windows-sys | schannel for ergonomic Rust API, windows-sys to fill gaps (physical stores, system store enumeration, auth) |
| Certificate parsing | x509-parser | Mature, zero-copy, full extension support. Complements schannel's raw DER output. |
| TUI framework | ratatui + crossterm | Industry standard for Rust TUIs. Supports all needed features (tables, scrolling, overlays, input). |
| Coexistence with cliclack | Alternate screen handoff | launch_certmgr() enters ratatui alternate screen, ratatui::restore() returns to cliclack. Clean boundary. |
| WinRT API | Rejected | Requires async runtime, poor CurrentUser/LocalMachine distinction, overkill for CLI. |
| Crate isolation | Separate ssl-toolbox-win-certstore | Keeps Windows-specific code out of ssl-toolbox-core, clean compilation boundary. |
| Format detection | Reuse ssl-toolbox-core::convert::detect_format() | Existing format detection extended with PKCS7 support. |

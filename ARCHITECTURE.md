# ssl-toolbox Architecture

Authoritative reference for the design, cryptographic contracts, and operational boundaries of the ssl-toolbox workspace.

> **Spec-first.** This document defines behavior. Tests encode this spec. Code satisfies those tests. If the code disagrees with the spec, fix the spec first, then the test, then the code.

---

## 1. Core Concepts

ssl-toolbox is a single-binary, cross-platform CLI for SSL/TLS certificate operations. It generates RSA keys and CSRs, builds and inspects PKCS#12 containers, verifies TLS endpoints over HTTPS/LDAPS/SMTP-STARTTLS, converts between certificate encodings, and optionally submits CSRs to a pluggable Certificate Authority backend.

The workspace is structured around a hard separation of concerns:

| Concern | Crate | Role |
|---|---|---|
| User interface | `ssl-toolbox` | clap commands, interactive cliclack menu, display formatting, persistent workspace state |
| Cryptographic primitives | `ssl-toolbox-core` | RSA/CSR generation, PFX build/inspect, TLS probing, format conversion, CSR config contracts |
| CA abstraction | `ssl-toolbox-ca` | `CaPlugin` trait, `CertProfile`, `SubmitOptions`, `CollectFormat` |
| Reference CA impl | `ssl-toolbox-ca-sectigo` | Sectigo Certificate Manager plugin, feature-gated |

The `CaPlugin` trait is the single extension seam. Adding a new CA vendor means implementing one trait in a new crate. The core library has no awareness of any CA vendor.

All cryptography runs against a **vendored OpenSSL 0.10** (the `openssl` crate with the `vendored` feature). There is no runtime dependency on a system OpenSSL, a system libcrypto, or a system trust store for operations that build artifacts. Chain validation during TLS verification still loads the platform's default trust paths (see Section 6).

---

## 2. Workspace & Crate Boundaries

The workspace is defined in [`Cargo.toml`](Cargo.toml) under `[workspace]`. All four member crates share `version = "2.0.1"` and `edition = "2024"` via `[workspace.package]`. Shared dependencies are declared once in `[workspace.dependencies]`.

### 2.1 `ssl-toolbox` (CLI binary)

Entry point: `crates/ssl-toolbox/src/main.rs`.

- `clap` (derive) provides all subcommands. The top-level `Cli` has a global `--debug` flag and an optional subcommand; no subcommand launches the interactive menu.
- `cliclack` drives the interactive workflow (menu, prompts, multiselect, spinners).
- `dotenvy::dotenv()` is called at startup; missing `.env` is non-fatal.
- `crossterm` is used by `display.rs` for terminal-width-aware rendering.
- State persistence (`settings.rs`, `workflow.rs`) serialises to `~/.ssl-toolbox/state.json` with `0o600` / parent dir `0o700` on Unix.

Depends on: `ssl-toolbox-core`, `ssl-toolbox-ca`, and `ssl-toolbox-ca-sectigo` (optional, via the `sectigo` feature).

### 2.2 `ssl-toolbox-core` (library)

Modules:

| Module | Responsibility |
|---|---|
| `cert_types` | `CertDetails`, `PfxDetails`, `ConfigInputs`, `CertValidation`, `CipherInfo`, `TlsCheckResult`, `CertFormat`, `CsrDefaults` — all shared data shapes |
| `key_csr` | `generate_key_and_csr`, `extract_csr_details` |
| `pfx` | `create_pfx`, `create_pfx_legacy`, `create_pfx_legacy_3des`, `extract_pfx_details`, `extract_pfx_bundle_details` |
| `tls` | `perform_tls_handshake`, `probe_tls_versions`, `connect_and_check` |
| `smtp` | `connect_and_check_smtp` |
| `validation` | `validate_peer_cert` (hostname, expiry, chain) |
| `x509_utils` | `x509_to_cert_details`, `extract_cert_chain_details`, `collect_peer_chain`, `extract_chain_from_ssl` |
| `convert` | `detect_format`, `pem_to_der`, `der_to_pem`, `pem_to_base64`, `format_description` |
| `config` | `generate_conf_from_inputs`, `generate_conf_from_cert_or_csr` |

Depends on: `anyhow`, `openssl` (vendored), `serde`, `serde_json`. No awareness of any CA vendor. No reqwest, no tokio, no async.

### 2.3 `ssl-toolbox-ca` (trait crate)

Single file: `crates/ssl-toolbox-ca/src/lib.rs`. Exports only:

- `trait CaPlugin: Send + Sync`
- `struct CertProfile { id, name, description, terms }`
- `struct SubmitOptions { description, product_code, term_days }`
- `enum CollectFormat { PemCert, PemChain, Pkcs7 }`

Depends on: `anyhow`, `serde`. No HTTP, no JSON, no crypto. This crate is always compiled, regardless of features.

### 2.4 `ssl-toolbox-ca-sectigo` (Sectigo implementation)

Implements `CaPlugin` against the Sectigo Certificate Manager REST API. Depends on `reqwest` (blocking, JSON) and `dotenvy`. Compiled only when the `sectigo` feature is enabled on the CLI crate.

### 2.5 Dependency rules

```
ssl-toolbox ──▶ ssl-toolbox-core
    │
    ├──▶ ssl-toolbox-ca
    │
    └──(feature sectigo)──▶ ssl-toolbox-ca-sectigo ──▶ ssl-toolbox-ca
```

- `ssl-toolbox-core` must never depend on `ssl-toolbox-ca` or any vendor crate.
- `ssl-toolbox-ca` must never depend on `ssl-toolbox-core` or any vendor crate.
- Vendor plugin crates depend only on `ssl-toolbox-ca` (plus their HTTP/serde stack).
- The CLI is the only crate that wires plugins into the trait.

### 2.6 Feature gate matrix

| Crate | `sectigo` on (default) | `sectigo` off |
|---|---|---|
| `ssl-toolbox` | Full CLI, `ca` subcommand wired to Sectigo | Full CLI, `ca` subcommand returns "No CA plugin compiled. Build with --features sectigo" |
| `ssl-toolbox-core` | Always built | Always built |
| `ssl-toolbox-ca` | Always built | Always built |
| `ssl-toolbox-ca-sectigo` | Built | Not built, not linked, no `reqwest` compiled |

`cargo check -p ssl-toolbox --no-default-features` must pass on every commit that lands on `main`.

---

## 3. Configuration Model

Configuration resolves through five ordered layers. **Later layers override earlier layers.**

| # | Source | Scope | Contents |
|---|---|---|---|
| 1 | Compiled defaults | Binary | Empty strings for `CsrDefaults`; `api_base = "https://cert-manager.com"` for `SectigoConfig` |
| 2 | `~/.ssl-toolbox/*.json` | User | `config.json` (CSR defaults), `sectigo.json` (CA plugin settings) |
| 3 | `./.ssl-toolbox/*.json` | Project | Same files as user scope; project values override user values |
| 4 | Environment variables / `.env` | Process | `SCM_CLIENT_ID`, `SCM_CLIENT_SECRET`, `SCM_TOKEN_URL`, `SECTIGO_API_BASE`, `SECTIGO_ORG_ID`, `SECTIGO_PRODUCT_CODE` |
| 5 | CLI flags | Invocation | `--conf`, `--key`, `--out`, `--host`, `--port`, `--no-verify`, `--full-scan`, `--legacy`, etc. |

### 3.1 File contracts

**`.ssl-toolbox/config.json`** — CSR defaults consumed by interactive prompts. Schema matches `CsrDefaults` in `ssl-toolbox-core`: `country`, `state`, `locality`, `organization`, `org_unit`, `email`. All fields are optional and default to empty strings. Only non-empty fields overlay the layer below (see `merge_csr_defaults`).

**`.ssl-toolbox/sectigo.json`** — Sectigo plugin settings. Schema matches `SectigoConfig`: `api_base`, `org_id`, `product_code`, `token_url`. `api_base` defaults to `https://cert-manager.com`.

**`.env`** — Secrets only. `SCM_CLIENT_ID` and `SCM_CLIENT_SECRET` are required when using any `ca` subcommand; `SCM_TOKEN_URL` is required and sourced from either env or `sectigo.json`. **Secrets must never appear in any `*.json` file.**

**`~/.ssl-toolbox/state.json`** — Private runtime state (recent paths, workflow memory, recent jobs, last menu choice). Written with mode `0o600`; the enclosing directory is set to `0o700`. Unix-only enforcement; Windows relies on NTFS ACLs inherited from `%USERPROFILE%`.

### 3.2 `init` command

`ssl-toolbox init` creates `./.ssl-toolbox/config.json` and `./.ssl-toolbox/sectigo.json` with template values if they do not already exist. Existing files are never overwritten.

`ssl-toolbox init --global` writes to `~/.ssl-toolbox/` instead. Either invocation returns the list of files actually written.

---

## 4. Key & CSR Generation

Implementation: `ssl-toolbox-core::key_csr`.

### 4.1 Key generation

- Algorithm: **RSA**
- Modulus size: **2048 bits**, hard-coded in `Rsa::generate(2048)`
- Encoding: **PKCS#8 PEM**
- Encryption: **AES-256-CBC** via `private_key_to_pem_pkcs8_passphrase` with `Cipher::aes_256_cbc()`
- Passphrase: required; no unencrypted key path exists in the generation pipeline

Rationale: 2048-bit RSA remains the CA/B Forum baseline and the broadest interoperability target. PKCS#8 + AES-256-CBC is the format produced by `openssl genpkey -aes-256-cbc` and is readable without flags by every current OpenSSL tool and mainstream TLS stack.

### 4.2 CSR generation

`generate_key_and_csr` consumes an OpenSSL-style `.cnf` file and produces a signed CSR:

1. Read `[ req_distinguished_name ]` — map each `KEY = value` to an X.509 Name entry by short name (`C`, `ST`, `L`, `O`, `OU`, `CN`, `emailAddress`) or, as a fallback, by looking up the OID via `Asn1Object::from_str`.
2. Read `[ alt_names ]` — entries whose key starts with `DNS`, `IP`, `email`, or `URI` are added to a `SubjectAlternativeName` extension.
3. Set the CSR public key to the generated RSA key.
4. Sign with **SHA-256**.
5. Write PEM to the CSR path.

Any key outside those prefixes is silently ignored. Subject OIDs that fail to resolve are skipped (never errored) to preserve forward compatibility with custom OIDs in legacy `.cnf` files.

### 4.3 SAN schema

| Prefix in `.cnf` | X.509 SAN type |
|---|---|
| `DNS.N` or `DNS` | `dNSName` |
| `IP.N` or `IP` | `iPAddress` (IPv4 or IPv6) |
| `email.N` or `email` | `rfc822Name` |
| `URI.N` or `URI` | `uniformResourceIdentifier` |

When re-extracting SANs from a parsed cert/CSR (`extract_sans`, `extract_csr_details`, `extract_sans_into`), IPv4 and IPv6 SANs are both rendered via `std::net::IpAddr` formatting — no raw byte dumps.

### 4.4 `.cnf` round-trip contract

`config::generate_conf_from_cert_or_csr(input, output, is_csr)` extracts the subject and SAN list from an existing PEM or DER artifact and writes a minimal `.cnf` file containing:

- `[ req ]` (empty stanza for round-trip)
- `[ req_distinguished_name ]` — subject fields by short name
- `[ v3_req ]` + `[ alt_names ]` if any SANs were present

The written file is *not* expected to be byte-identical to an input `.cnf`; it is a valid OpenSSL config that will regenerate a CSR with the same subject and SANs.

`config::generate_conf_from_inputs(inputs, path)` writes a fully-featured `.cnf` with `default_md = sha256`, `prompt = no`, `basicConstraints = CA:FALSE`, `keyUsage = critical, digitalSignature, keyEncipherment`, an `extendedKeyUsage` driven by `ConfigInputs`, and a `subjectKeyIdentifier = hash`. The CN is always inserted as `DNS.1` in `[ alt_names ]` to prevent CN-only leaf certs.

---

## 5. PFX / PKCS12

Implementation: `ssl-toolbox-core::pfx`.

### 5.1 Profiles

| Profile | Key encryption | Cert encryption | MAC digest | Entry point |
|---|---|---|---|---|
| Modern | OpenSSL 3.x default (AES-256-CBC / PBES2) | OpenSSL 3.x default | SHA-256 | `create_pfx` |
| Legacy | `PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC` | `PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC` | SHA-1 | `create_pfx_legacy`, `create_pfx_legacy_3des` |

The modern profile is produced by `Pkcs12::builder().build2(pfx_password)` without overriding `key_algorithm` / `cert_algorithm` / `mac_md`, which yields OpenSSL's secure default (AES-256-SHA256, aka "AES-256-CBC with SHA-256 MAC").

The legacy profile is selected by `--legacy` on `pfx` or by the dedicated `pfx-legacy` subcommand. It exists exclusively for interop with pre-2019 Windows Server, Java 8, and certain hardware appliances that cannot read modern PFX.

### 5.2 Input handling

- Private key input: PEM, either unencrypted or encrypted. If parsing unencrypted fails, a passphrase is required; a missing passphrase on an encrypted key returns `"Private key is encrypted but no password was provided"`.
- Certificate input: PEM. `X509::stack_from_pem` is used so that concatenated PEM bundles are handled as chains. If multiple certs are present, the **last** cert in the file is treated as the leaf and all prior certs become the CA chain; the `--chain` argument is ignored in that case.
- Chain input: optional separate PEM file, used only when the cert file contains exactly one certificate.

### 5.3 Modern ↔ legacy conversion

`create_pfx_legacy_3des(input_pfx_bytes, input_password, output_file, output_password)` parses an existing PFX, extracts the private key and leaf cert (plus any CA chain), and rebuilds a fresh PKCS#12 container under the legacy profile. It requires a non-empty `pkey` in the input; a chain-only PFX (no private key) is a hard error.

The reverse direction (legacy → modern) is not a dedicated operation; re-running `pfx` with the unpacked key and cert produces a modern PFX.

### 5.4 Viewer output contract

`view-pfx` (powered by `extract_pfx_bundle_details`) must report, for each cert in the bundle:

- Common Name
- Subject Alternative Names (DNS, IP, Email, URI)
- Not-before / not-after
- Issuer CN (or Organization if no CN)
- Signature algorithm
- Public key bits
- Serial number (hex)
- SHA-1 and SHA-256 fingerprints (colon-delimited)

Plus a `PrivateKeySummary` block containing `present`, `algorithm` (`RSA`/`DSA`/`DH`/`EC`/`Unknown`), `key_size_bits`, `security_bits`, and `matches_leaf_certificate` (determined by comparing the PFX private key's public part against the leaf cert's public key).

An empty cert list is a hard error (`"No certificates found in PFX file"`). A PFX with no private key is permitted; `present` is set to `false`.

---

## 6. TLS Verification

Implementation: `ssl-toolbox-core::tls` (HTTPS/LDAPS) and `ssl-toolbox-core::smtp` (SMTP STARTTLS).

### 6.1 Probe contracts

| Command | Default port | Transport | Upgrade |
|---|---|---|---|
| `verify-https` | 443 | Direct TLS | — |
| `verify-ldaps` | 636 | Direct TLS | — |
| `verify-smtp` | 587 | Plaintext SMTP → STARTTLS | EHLO → STARTTLS → TLS handshake |

All probes use a **10-second TCP connect timeout** and **10-second read/write timeouts**.

### 6.2 Report fields

Every verification populates a `TlsCheckResult` with:

- `host`, `port`
- `cipher: CipherInfo` — negotiated cipher's standard name (falling back to OpenSSL internal name), secret bits, and TLS version string
- `cert_chain: Vec<CertDetails>` — leaf-first, deduplicated by DER
- `version_support: Vec<TlsVersionProbeResult>` — per-protocol handshake result for TLS 1.0, 1.1, 1.2, 1.3 (empty for SMTP; see 6.4)
- `cipher_scan: Vec<TlsCipherScanResult>` — populated only when `--full-scan` is passed
- `validation: Option<CertValidation>` — populated only when verification is enabled

`CertValidation` covers three independent checks:

| Check | Pass condition |
|---|---|
| `hostname_match` | RFC 6125 — SAN DNS entries match first (case-insensitive, wildcards restricted to a single label via `*.domain.tld`). CN fallback only fires if no `dNSName` SAN exists on the cert. |
| `expiry_check` | `not_before ≤ now ≤ not_after` |
| `chain_valid` | Chain verifies against the system default trust store (`X509StoreBuilder::set_default_paths`) |

### 6.3 Full-scan model

When `--full-scan` is passed to `verify-https` or `verify-ldaps`, the tool runs protocol-pinned handshakes for each locally testable cipher suite, per protocol version:

- TLS 1.0 / TLS 1.1: 11 named ciphers (ECDHE/DHE + RSA/DSA + AES-128/256 + DES-CBC3)
- TLS 1.2: 26 named ciphers (GCM + CBC + CHACHA20-POLY1305)
- TLS 1.3: 5 named ciphers (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`, `TLS_AES_128_CCM_SHA256`, `TLS_AES_128_CCM_8_SHA256`)

A cipher is **locally testable** when the vendored OpenSSL accepts it via `set_cipher_list` (non-1.3) or `set_ciphersuites` (1.3). The report's `tested_cipher_count` reflects the locally testable subset for each protocol — *not* the superset. A cipher that the vendored build cannot load (e.g., EXPORT/NULL suites) is silently skipped; there is no attempt to reach suites unavailable locally.

Ciphers on protocols the server rejected in the version probe are not tested. A server that refuses TLS 1.0 will report an empty `supported_ciphers` for TLS 1.0, not one failure per cipher.

### 6.4 SMTP STARTTLS

`connect_and_check_smtp`:

1. Opens TCP to `host:port`.
2. Reads the `220` greeting (multi-line aware — reads until the fourth byte of a line is a space).
3. Sends `EHLO ssl-toolbox\r\n`; requires a `250` response that advertises `STARTTLS`.
4. Sends `STARTTLS\r\n`; requires a `220` response.
5. Upgrades the socket to TLS using default `SslConnector::builder(SslMethod::tls())`. Verification is always disabled during the handshake; chain/hostname/expiry are re-evaluated afterwards via `validate_peer_cert` when the caller passes `verify = true`.

SMTP does **not** populate `version_support` or `cipher_scan`. Reconnecting for each protocol version would require redoing the SMTP preamble every time; that cost is not amortised until demand appears.

### 6.5 `--no-verify` semantics

`--no-verify` disables **chain validation only**. Hostname match, expiry, negotiated cipher, version probing, and chain extraction are all still performed and reported. The `validation` field is set to `None` when `--no-verify` is passed; otherwise it contains all three sub-checks.

---

## 7. Format Tools

Implementation: `ssl-toolbox-core::convert`.

### 7.1 Convert matrix

| From → To | PEM | DER | Base64 (raw) |
|---|---|---|---|
| PEM | — | `pem_to_der` | `pem_to_base64` (76-char wrap) |
| DER | `der_to_pem` | — | *(use DER → PEM → Base64)* |
| Base64 | *(use Base64 → DER manually)* | *(decode Base64)* | — |

The `convert` subcommand accepts `--format pem|der|base64`. All conversions operate on X.509 certificates; PKCS#12 and PKCS#7 are inspected by `identify` but not converted by `convert`.

### 7.2 Auto-detect algorithm

`detect_format` inspects the payload in this order:

1. PKCS#7 PEM markers (`-----BEGIN PKCS7-----` or `-----BEGIN CMS-----`) → `Pkcs7`
2. Any other `-----BEGIN ` marker → `Pem`
3. PKCS#7 DER OID `1.2.840.113549.1.7.2` found in the first 30 bytes → `Pkcs7`
4. `Pkcs12::from_der` succeeds → `Pkcs12`
5. `X509::from_der` succeeds → `Der`
6. Body is ASCII-safe base64 alphabet with no `-----` markers and decodes successfully → `Base64`
7. Otherwise → `Unknown`

Ordering matters: PKCS#7 PEM must be detected **before** generic PEM so that `-----BEGIN PKCS7-----` does not fall through to the X.509 PEM branch. This ordering is locked by unit tests in the `convert` module.

---

## 8. CA Plugin Trait

Defined in `ssl-toolbox-ca/src/lib.rs`.

```rust
pub trait CaPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn list_profiles(&self, debug: bool) -> Result<Vec<CertProfile>>;
    fn submit_csr(&self, csr_pem: &str, options: &SubmitOptions, debug: bool) -> Result<String>;
    fn collect_cert(&self, request_id: &str, format: CollectFormat, debug: bool) -> Result<String>;
}
```

### 8.1 Contract

| Method | Input | Output | Error surface |
|---|---|---|---|
| `name()` | — | Human-readable plugin name | Infallible |
| `list_profiles(debug)` | debug flag | Vector of `CertProfile` | `anyhow::Result` — network, auth, parse errors |
| `submit_csr(csr_pem, options, debug)` | PEM CSR, options, debug flag | CA-assigned request/order ID as `String` | `anyhow::Result` — submission failure or missing ID |
| `collect_cert(request_id, format, debug)` | ID from `submit_csr`, target format | Certificate payload as `String` (PEM or base64 PKCS#7) | `anyhow::Result` — not-ready, auth, format errors |

### 8.2 Shared types

```rust
pub struct CertProfile { id: String, name: String, description: Option<String>, terms: Vec<i32> }
pub struct SubmitOptions { description: Option<String>, product_code: Option<String>, term_days: Option<i32> }
pub enum CollectFormat { PemCert, PemChain, Pkcs7 }
```

- `CertProfile::id` is an opaque string — any CA may use numeric IDs, GUIDs, or slugs.
- `CertProfile::terms` is the list of validity lengths in **days** the CA offers for that profile.
- `SubmitOptions::product_code` matches a `CertProfile::id`. If `None`, the plugin may pick a vendor default.
- `SubmitOptions::term_days` must be one of the profile's supported terms, or `None` to let the plugin pick (typically the longest available).

### 8.3 Adding a new plugin

1. Create a new crate `ssl-toolbox-ca-<vendor>` that depends on `ssl-toolbox-ca`.
2. Define a config struct (`Serialize + Deserialize + Default`) — mirror `SectigoConfig`'s shape.
3. Define a plugin struct and implement `CaPlugin` for it. Keep `Send + Sync`.
4. Provide a `configure_with_config(&Config, debug) -> Result<Box<dyn CaPlugin>>` constructor that reads any required secrets from environment variables (never from the JSON config).
5. Add a feature flag `<vendor>` on the `ssl-toolbox` crate, gate the dependency behind `dep:ssl-toolbox-ca-<vendor>`, and wire `get_ca_plugin` behind `#[cfg(feature = "<vendor>")]`.
6. Update this document and `CHANGELOG.md`.

---

## 9. Sectigo Integration

Implementation: `ssl-toolbox-ca-sectigo/src/lib.rs`.

### 9.1 Authentication

OAuth 2.0 **client credentials** grant, `application/x-www-form-urlencoded`:

```
POST $SCM_TOKEN_URL
grant_type=client_credentials
client_id=$SCM_CLIENT_ID
client_secret=$SCM_CLIENT_SECRET
```

Response: `{ "access_token": "..." }`. The token is fetched fresh on every API call — there is no in-memory cache. Tokens never reach logs or error output; only `client_id.len()` and the token URL appear under `--debug`.

### 9.2 Configuration sources

| Setting | Env variable | JSON key | Required |
|---|---|---|---|
| API base URL | `SECTIGO_API_BASE` | `api_base` | No (defaults to `https://cert-manager.com`) |
| Organisation ID | `SECTIGO_ORG_ID` | `org_id` | Yes for submit/list |
| Default product code | `SECTIGO_PRODUCT_CODE` | `product_code` | No |
| Token URL | `SCM_TOKEN_URL` | `token_url` | Yes |
| Client ID | `SCM_CLIENT_ID` | **never** | Yes |
| Client secret | `SCM_CLIENT_SECRET` | **never** | Yes |

Environment variables override JSON. Missing `SCM_CLIENT_ID`/`SCM_CLIENT_SECRET` aborts plugin construction. Missing `SCM_TOKEN_URL` (neither env nor JSON) aborts plugin construction.

### 9.3 Endpoints

| Operation | Method | Path | Auth | Notes |
|---|---|---|---|---|
| List profiles | `GET` | `/api/ssl/v2/types?organizationId=<org_id>` | Bearer | Returns array of `{id, name, description?, terms[], keyTypes?, useSecondaryOrgName}` |
| Submit CSR | `POST` | `/api/ssl/v1/enroll` | Bearer | JSON body: `{certType, csr (stripped), orgId, term}`. Response: `{sslId: i64}` |
| Attach description | `PUT` | `/api/ssl/v1` | Bearer | JSON body: `{sslId, comments}`. Failure is warned, not fatal |
| Collect | `GET` | `/api/ssl/v1/collect/<id>?format=<fmt>` | Bearer | Format token per table below |

All HTTP requests disable automatic redirects (`reqwest::redirect::Policy::none()`) to prevent silent base-URL drift.

### 9.4 Collection format mapping

| `CollectFormat` | Sectigo `format=` value |
|---|---|
| `PemCert` | `x509` |
| `PemChain` | `x509CO` |
| `Pkcs7` | `pkcs7` |

### 9.5 Term selection

`submit_csr` fetches the profile list, finds the profile whose ID matches `options.product_code` (or the configured default), and selects a term:

- If `options.term_days` is `Some(t)`, that value is sent as-is.
- Otherwise, the **largest** value in `profile.terms` is selected.

A missing profile or an empty `terms` list is a hard error.

### 9.6 CSR formatting

The CSR PEM passed to `submit_csr` has its `-----BEGIN`/`-----END` lines stripped and all body lines concatenated into a single base64 blob before being placed in the JSON payload. This matches the Sectigo API contract (`csr` is a plain base64 string, not PEM).

### 9.7 Error surface and retries

There is **no automatic retry**. Any non-2xx response returns an `anyhow::Error` with status and body text (status and body are also printed on submit errors; body is only printed on list/collect errors when `--debug` is set). Bearer token 401s propagate as errors — the caller re-runs the command to get a fresh token.

---

## 10. Interactive Workflow & Persistent State

Implementation: `ssl-toolbox/src/workflow.rs`, `ssl-toolbox/src/settings.rs`, `ssl-toolbox/src/display.rs`, interactive handlers in `ssl-toolbox/src/main.rs`.

### 10.1 Menu model

Running `ssl-toolbox` with no subcommand launches an interactive menu built on `cliclack`. Each menu entry is a `PaletteEntry` with:

- `action` (integer used for routing)
- `alias` (short string for command-palette search, e.g. `g`, `pfx`, `legacy`)
- `title` (human label)
- `description` (one-line explanation)
- `keywords` (search synonyms)

A built-in command palette (`search_palette`) ranks entries by alias equality (120) > title equality (115) > prefix (100/95) > keyword match (90/80) > title substring (70) > description substring (60) > subsequence (40/35). Exact matches always beat substring matches; ties break on title alphabetically.

### 10.2 Persistent state

Serialized to `~/.ssl-toolbox/state.json`:

```rust
struct UiState {
    recent_paths: BTreeMap<String, String>,
    last_menu_choice: String,
    workflow: WorkflowMemory,
    recent_jobs: Vec<JobRecord>,
}
```

`WorkflowMemory` holds the currently-active artifacts (config, key, csr, cert, chain, pfx, legacy_pfx) and endpoint hosts (https_host, ldaps_host, smtp_host) along with the **active profile**. The interactive menu pre-fills prompts from `WorkflowMemory` and from the last-used value in `recent_paths`.

### 10.3 Active profile

A profile is a named configuration bundle for a specific cert subject (the value of `workflow.active_profile`). Selecting a profile scopes prompts to that profile's recent artifacts. Profile names are free-form strings; there is no registry of profile names outside what has been stored in state.

### 10.4 Recent jobs

Every successful action appends a `JobRecord` to `recent_jobs`:

```rust
struct JobRecord {
    kind: ActionKind,
    summary: String,
    inputs: BTreeMap<String, String>,
    outputs: BTreeMap<String, String>,
    replay_data: BTreeMap<String, String>,
    profile: Option<String>,
    timestamp_secs: u64,
}
```

The list is capped at **20 most-recent entries** (`push_recent_job` inserts at index 0 then truncates to 20). Re-applying a job's inputs/outputs through `apply_job_to_workflow` restores the artifact map. `replay_data` carries action-specific parameters (key size, EKU, etc.) that the menu can use to pre-fill a rerun.

### 10.5 Workspace scanning

`WorkspaceSnapshot::scan(root)` walks up to 4 directory levels below `root`, skipping `.git`, `target`, `.ssl-toolbox`, `.claude`, and `node_modules`, and classifies files by extension and filename:

| Extension | `ArtifactKind` |
|---|---|
| `.cnf` / `.conf` | `Config` |
| `.key` | `Key` |
| `.csr` | `Csr` |
| `.crt` / `.cer` | `Cert` (or `Chain` if name contains `chain`) |
| `.pem` | `Key` / `Csr` / `Cert` depending on filename suffix |
| `.pfx` / `.p12` | `Pfx` (or `LegacyPfx` if name contains `legacy`) |
| `.p7b` / `.p7c` (with `chain` in name) | `Chain` |

The scan is capped at **200 files**. The detected workflow is the family (by file stem) with the highest score, with a bonus for having both a cert and a key.

### 10.6 CLI / menu parity

Every CLI subcommand has a menu entry, and every menu entry invokes the same underlying `ssl-toolbox-core` function. The menu never unlocks capability the CLI lacks; the CLI never unlocks capability the menu lacks.

---

## 11. Threat Model

### 11.1 What ssl-toolbox protects against

| Threat | Mitigation |
|---|---|
| CSR subject typos | Interactive prompts validate format; extracted config preserves subject from existing certs |
| Wrong format shipped to a CA or system | `identify` command auto-detects PEM/DER/Base64/PKCS#7/PKCS#12 |
| Weak key crypto by default | RSA-2048 + AES-256-CBC PKCS#8 hard-coded; no option for < 2048-bit |
| Weak PFX crypto by default | Modern profile (AES-256 + SHA-256 MAC) is default; legacy is opt-in only |
| MITM on verification | Chain validation against system trust store by default; `--no-verify` is explicit and documented |
| Hostname mismatch going unnoticed | SAN check follows RFC 6125; CN fallback only when no SAN DNS entries exist |
| Expired cert deployed unnoticed | `expiry_check` runs on every verify by default |
| Weak ciphers deployed unnoticed | `--full-scan` enumerates negotiable ciphers per protocol |
| Token/password leaked to disk | Secrets live in `.env` (gitignorable) or env vars; never written to `*.json`; state files are mode `0o600` |

### 11.2 What ssl-toolbox does NOT protect against

- **Compromised host.** A root/administrator on the running host can read private keys, `.env`, state.json, and memory directly. Disk-level encryption and OS user isolation are the owner's responsibility.
- **Malicious system libc / loader.** The vendored OpenSSL mitigates system-OpenSSL tampering but not libc, dynamic loader, or ptrace attacks.
- **Key exfiltration via side channels.** No constant-time guarantees are made beyond what OpenSSL provides.
- **Malicious input CSR / cert that exploits OpenSSL parsing.** The tool is only as safe as the vendored OpenSSL version it is built against.
- **Sectigo account compromise.** If `SCM_CLIENT_SECRET` is stolen, the attacker can issue/collect certs under that account. Credential rotation is out of scope.
- **Stolen PFX files.** PFX passphrase strength is the user's responsibility; the tool does not enforce a minimum.

### 11.3 Secret handling rules

1. Secrets (`SCM_CLIENT_ID`, `SCM_CLIENT_SECRET`, key passphrases, PFX passphrases) must never be printed to stdout or stderr, including under `--debug`.
2. Secrets must never be written to JSON configuration files. The CA plugin config file is for non-secret operational parameters only.
3. Passphrases entered at interactive prompts are masked (`cliclack::password`).
4. On Unix, state files containing recent paths and workflow memory are written with mode `0o600` inside a `0o700` directory.
5. Error messages about missing secrets must name the env variable, never its expected value.

### 11.4 Vendored OpenSSL trust boundary

ssl-toolbox bundles a statically-linked OpenSSL via the `openssl` crate's `vendored` feature. This means:

- A system OpenSSL CVE does not affect the binary until rebuilt.
- Conversely, a vendored OpenSSL CVE requires a new ssl-toolbox release; users cannot patch it by upgrading their system package.
- **FIPS 140 mode is not supported.** The vendored build does not compile the FIPS provider, and ssl-toolbox exposes no API to select it. Environments requiring FIPS must use a platform-native tool.
- The trust store used for chain validation still comes from the system (`X509_DEFAULT_CERT_DIR` / `X509_DEFAULT_CERT_FILE` resolved by `X509StoreBuilder::set_default_paths`). The OpenSSL library is vendored; the CA bundle it reads is not.

---

## 12. Design Principles

1. **Modern crypto by default; legacy opt-in only.** RSA-2048, AES-256-CBC, SHA-256 are hard-coded defaults. Legacy PFX (TripleDES-SHA1) requires an explicit `--legacy` flag or the `pfx-legacy` subcommand.
2. **Feature-gate all CA dependencies.** A `--no-default-features` build must produce a working binary with no vendor plugin code linked in.
3. **Never print secrets.** Tokens, passwords, client IDs, and client secrets are never emitted to stdout, stderr, logs, or error messages — regardless of `--debug`.
4. **Vendored OpenSSL.** No system OpenSSL dependency. The binary is reproducible across Linux, macOS, and Windows without platform crypto libraries.
5. **Single binary, no runtime deps.** One executable. No JRE, no Python, no shared libraries beyond libc/kernel32.
6. **CLI and interactive menu reach feature parity.** Every subcommand has a menu entry; every menu entry exists as a subcommand.
7. **Config layering is strict: CLI > env > project > user > defaults.** No other precedence exists. Later layers override earlier layers non-transitively (only non-empty fields overlay).
8. **Test against the spec, not the implementation.** If a test fails, either the spec is wrong or the code is wrong — never silently relax the test to match the code.
9. **No CA awareness in the core library.** `ssl-toolbox-core` must compile without `ssl-toolbox-ca` in its dependency graph.
10. **Timeouts are non-optional.** Every network operation has a hard timeout (10s for TCP/TLS, no retry). The tool never hangs on a stuck server.

---

## 13. Known Tradeoffs

Every tradeoff listed below is deliberate. Contributors changing any of these must update this section in the same PR.

### Vendored OpenSSL blocks FIPS mode

The `vendored` feature compiles OpenSSL from source without the FIPS provider. Users who need FIPS 140-2/140-3 validation cannot use ssl-toolbox for those workflows.

**Accepted because:** cross-platform portability across a single statically-linked binary is worth more than FIPS support for the target audience (engineers doing certificate plumbing, not regulated-environment operators). FIPS customers have platform-native tooling already.

### AES-CBC (not GCM) for encrypted keys

`generate_key_and_csr` encrypts the private key with AES-256-CBC in PKCS#8, not AES-256-GCM. GCM offers authenticated encryption; CBC does not.

**Accepted because:** OpenSSL CLI compatibility. The `openssl pkey -in key.pem` command reads PKCS#8+AES-CBC without flags on every OpenSSL version in use. PKCS#8+GCM requires newer OpenSSL and is not the lingua franca of certificate tooling. Integrity of the key file is a filesystem concern, not a format concern.

### Cipher scan is "locally testable" only

`--full-scan` probes the ciphers that the vendored OpenSSL can load, not the superset a server could theoretically offer. A server advertising an EXPORT suite or a PSK-only suite that the vendored build omits will not appear in the scan output.

**Accepted because:** the alternative is running a second scanner (nmap, testssl.sh) that the user already has available if they want that depth. ssl-toolbox reports what its own crypto stack can negotiate — which matches what a real client running against the same OpenSSL would actually accept. A scan that lists ciphers the tool cannot verify is worse than a scan scoped to what it can.

### `--legacy` PFX uses deprecated crypto

TripleDES-SHA1 is no longer considered strong; SHA-1 is collision-broken and TripleDES is at 112-bit effective strength.

**Accepted because:** Windows Server 2012, Java 8, and several hardware load balancers in production today cannot read any other PFX profile. Shipping the legacy option is the only way to prevent users from generating PFX files by hand with openssl and mis-configuring them. The flag name (`--legacy`) and the separate subcommand (`pfx-legacy`) make the choice explicit at every invocation site.

### SMTP STARTTLS has no version probing or cipher scan

`verify-smtp` reports only the negotiated cipher and certificate data; `version_support` and `cipher_scan` are empty.

**Accepted because:** every additional TLS handshake against an SMTP server requires a full plaintext EHLO→STARTTLS preamble and a fresh TCP connection. That is 5 roundtrips per cipher suite per protocol version. The cost is not yet justified. If demand appears, the feature lives behind a future `--full-scan` flag that inherits the HTTPS probing model.

### No certificate chain re-ordering at build time

`create_pfx` treats the last PEM in a multi-cert file as the leaf and every earlier cert as a chain entry — a positional convention, not a graph walk. A user who concatenates their chain bottom-up ends up with an inverted bundle.

**Accepted because:** certificate files are already ambiguous enough; a "smart" re-order would silently fix some inputs and subtly corrupt others (intermediate with matching CN but different serial, cross-signed CAs, etc.). The rule "leaf is last" matches every `cat leaf.crt chain.crt > bundle.pem` convention in the wild, is easy to document, and puts responsibility on the file's author rather than a heuristic.

### Chain validation still uses the system trust store

Even though OpenSSL is vendored, `validate_chain` calls `X509StoreBuilder::set_default_paths`, which reads the host's CA bundle (`/etc/ssl/certs`, macOS Keychain exports, Windows cert store on some builds, etc.).

**Accepted because:** building a trust store into the binary means either shipping Mozilla's bundle (which then goes stale between releases) or distrusting every enterprise internal CA by default. The host trust store is already the owner's source of truth for what they trust; re-using it is the principle of least surprise. A future `--ca-bundle` flag could override this per-invocation if demand appears.

### `term_days` on Sectigo submission defaults to the longest available

When `options.term_days` is `None`, the plugin picks `*profile.terms.iter().max()`. A CA that lists `[90, 365, 730]` will default to 730 days.

**Accepted because:** for the overwhelming majority of ssl-toolbox users, "longest available" is what they want — fewer renewals. Users with a specific term requirement pass `--term` (future flag; currently set via `SubmitOptions` from the interactive menu). Short-dated certs are still reachable through the API; only the default changes.

---

## See Also

- [README.md](README.md) — user-facing overview and quick start
- [CONTRIBUTING.md](CONTRIBUTING.md) — TDD workflow, PR requirements, CI gates
- [CHANGELOG.md](CHANGELOG.md) — release history
- [docs/USER_MANUAL.md](docs/USER_MANUAL.md) — detailed per-command usage

# ssl-toolbox User Manual

## Table of Contents

- [Getting Started](#getting-started)
  - [Installation](#installation)
  - [First Run](#first-run)
  - [Configuration](#configuration)
- [Interactive Mode](#interactive-mode)
- [CLI Commands](#cli-commands)
  - [init](#init)
  - [generate](#generate)
  - [new-config](#new-config)
  - [config](#config)
  - [pfx](#pfx)
  - [pfx-legacy](#pfx-legacy)
  - [view-cert](#view-cert)
  - [view-csr](#view-csr)
  - [view-pfx](#view-pfx)
  - [verify-https](#verify-https)
  - [verify-ldaps](#verify-ldaps)
  - [verify-smtp](#verify-smtp)
  - [convert](#convert)
  - [identify](#identify)
  - [ca list-profiles](#ca-list-profiles)
  - [ca submit](#ca-submit)
  - [ca collect](#ca-collect)
- [Configuration In Depth](#configuration-in-depth)
  - [Config File Locations](#config-file-locations)
  - [config.json Reference](#configjson-reference)
  - [sectigo.json Reference](#sectigojson-reference)
  - [Environment Variables](#environment-variables)
  - [Layering and Precedence](#layering-and-precedence)
- [Workflows](#workflows)
  - [Generate a CSR and Key](#workflow-generate-a-csr-and-key)
  - [Submit to Sectigo and Create PFX](#workflow-submit-to-sectigo-and-create-pfx)
  - [Verify a TLS Endpoint](#workflow-verify-a-tls-endpoint)
  - [Convert Certificate Formats](#workflow-convert-certificate-formats)
  - [Migrate a PFX to Legacy Format](#workflow-migrate-a-pfx-to-legacy-format)
- [OpenSSL Config File Format](#openssl-config-file-format)
- [Certificate Formats](#certificate-formats)
- [Troubleshooting](#troubleshooting)

---

## Getting Started

### Installation

**Build from source** (requires Rust 1.85+):

```bash
cargo build --release -p ssl-toolbox
```

The binary is at `target/release/ssl-toolbox`. Copy it to a directory on your `PATH`:

```bash
cp target/release/ssl-toolbox /usr/local/bin/   # macOS/Linux
```

OpenSSL is vendored into the build -- there are no runtime dependencies or system OpenSSL requirements.

**Without Sectigo CA support** (smaller binary, no network dependencies):

```bash
cargo build --release -p ssl-toolbox --no-default-features
```

### First Run

1. **Initialize config files** with your organization defaults:

   ```bash
   ssl-toolbox init --global    # creates ~/.ssl-toolbox/config.json and sectigo.json
   ```

2. **Edit `~/.ssl-toolbox/config.json`** to set your default CSR values:

   ```json
   {
     "country": "US",
     "state": "Texas",
     "locality": "Dallas",
     "organization": "Acme Corp",
     "org_unit": "Engineering",
     "email": "certs@acme.com"
   }
   ```

3. **Launch the interactive menu**:

   ```bash
   ssl-toolbox
   ```

   Or use CLI commands directly -- see [CLI Commands](#cli-commands) below.

### Configuration

ssl-toolbox looks for config in two directories, merged in order:

1. `~/.ssl-toolbox/` -- user-level defaults (shared across all projects)
2. `./.ssl-toolbox/` -- project-level overrides (per-directory)

Environment variables and CLI flags override both. See [Configuration In Depth](#configuration-in-depth) for full details.

---

## Interactive Mode

Running `ssl-toolbox` with no arguments opens a menu-driven interface. Each action prompts for all required inputs with defaults pulled from your config files.

**Menu options:**

| # | Action | Description |
|---|---|---|
| 0 | Generate Key and CSR | Provide an OpenSSL `.cnf` file, get a `.key` and `.csr` |
| 1 | Create PFX | Combine a key + signed cert (+ optional chain) into a `.pfx` |
| 2 | Create Legacy PFX | Re-encrypt an existing PFX with TripleDES-SHA1 |
| 3 | Generate New OpenSSL Config | Answer prompts (CN, SANs, key size, etc.) to build a `.cnf` |
| 4 | Generate Config from Cert/CSR | Extract a `.cnf` from an existing `.crt` or `.csr` file |
| 5 | View Certificate Details | Display CN, SANs, issuer, and validity for a cert file |
| 6 | View CSR Details | Display CN and SANs for a CSR file |
| 7 | View PFX Contents | Decrypt a PFX and show all certificates inside |
| 8 | Verify HTTPS Endpoint | Connect to an HTTPS server and report TLS details |
| 9 | Verify LDAPS Endpoint | Connect to an LDAPS server and report TLS details |
| 10 | Verify SMTP Endpoint | Connect via SMTP STARTTLS and report TLS details |
| 11 | Convert Certificate Format | Convert between PEM, DER, and Base64 |
| 12 | Identify Certificate Format | Auto-detect a file's certificate format |
| 13 | CA: Submit CSR | Submit a CSR to Sectigo for signing *(Sectigo feature only)* |
| 14 | CA: List Profiles | List available certificate types from Sectigo *(Sectigo feature only)* |
| 99 | Exit | Close the application |

Options 13 and 14 only appear when the binary is built with the `sectigo` feature (the default).

**Smart defaults:** When generating a new OpenSSL config (option 3), each prompt shows the default value from your config file. Press Enter to accept a default, or type a new value.

**Path suggestions:** When the tool can guess an output filename (e.g., `server.cnf` leads to `server.key` and `server.csr`), it suggests it as a default.

---

## CLI Commands

Every command accepts the global `--debug` flag for verbose output:

```bash
ssl-toolbox --debug <command> [args]
```

### init

Generate template configuration files.

```bash
ssl-toolbox init             # creates .ssl-toolbox/ in current directory
ssl-toolbox init --global    # creates ~/.ssl-toolbox/
```

| Flag | Description |
|---|---|
| `--global` | Write to `~/.ssl-toolbox/` instead of `./.ssl-toolbox/` |

Creates two files (skips any that already exist):

- `config.json` -- CSR default values
- `sectigo.json` -- Sectigo plugin settings

### generate

Generate an RSA private key and CSR from an OpenSSL configuration file.

```bash
ssl-toolbox generate --conf openssl.cnf --key server.key --csr server.csr
ssl-toolbox generate --conf openssl.cnf --key server.key --csr server.csr --password "s3cret"
```

| Flag | Required | Description |
|---|---|---|
| `--conf`, `-c` | Yes | Path to OpenSSL `.cnf` config file |
| `--key`, `-k` | Yes | Output path for the private key |
| `--csr` | Yes | Output path for the CSR |
| `--password`, `-p` | No | Key encryption password (prompted if omitted) |

**Details:**
- Generates a 2048-bit RSA key
- Key is encrypted with AES-256-CBC (PKCS#8 format)
- CSR is signed with SHA-256
- Reads subject fields from `[req_distinguished_name]` and SANs from `[alt_names]`
- Supports all standard X.509 name fields: `C`, `ST`, `L`, `O`, `OU`, `CN`, `emailAddress`
- SAN types: `DNS.N`, `IP.N`, `email.N`, `URI.N`

### new-config

Interactively build a new OpenSSL configuration file from scratch.

```bash
ssl-toolbox new-config
ssl-toolbox new-config --out server.cnf
```

| Flag | Required | Description |
|---|---|---|
| `--out`, `-o` | No | Output file path (prompted if omitted, defaults to `<CN>.cnf`) |

**Prompts include:**
- Common Name (CN)
- Country, State, Locality, Organization, OU, Email (defaults from config)
- Additional DNS SANs (enter blank to stop)
- IP SANs (enter blank to stop)
- Key size: 2048 (default) or 4096
- Extended Key Usage: Server Auth, Client Auth, or Both (mTLS)

The CN is automatically included as `DNS.1` in the SANs section.

A summary is displayed before writing. You must confirm to proceed.

### config

Generate an OpenSSL configuration file from an existing certificate or CSR.

```bash
ssl-toolbox config --input server.crt --out server.cnf
ssl-toolbox config --input server.csr --out server.cnf --is-csr
```

| Flag | Required | Description |
|---|---|---|
| `--input`, `-i` | Yes | Input certificate (`.crt`, `.cer`, `.pem`) or CSR (`.csr`) file |
| `--out`, `-o` | Yes | Output `.cnf` file path |
| `--is-csr` | No | Treat input as a CSR instead of a certificate |

Extracts the subject distinguished name and SANs (DNS, IP, email, URI) from the input and writes a valid OpenSSL config file that can be used with `generate`.

### pfx

Create a PFX/PKCS12 file from a private key and signed certificate.

```bash
ssl-toolbox pfx --key server.key --cert server.crt --out server.pfx
ssl-toolbox pfx --key server.key --cert server.crt --out server.pfx --chain chain.crt
ssl-toolbox pfx --key server.key --cert server.crt --out server.pfx --legacy
```

| Flag | Required | Description |
|---|---|---|
| `--key`, `-k` | Yes | Path to private key file |
| `--cert`, `-c` | Yes | Path to signed certificate file |
| `--out`, `-o` | Yes | Output PFX file path |
| `--chain` | No | Separate chain/intermediate certificate file |
| `--legacy` | No | Use TripleDES-SHA1 encryption instead of modern AES-256-SHA256 |

**Password prompts:**
1. Private key password (press Enter if the key is not encrypted)
2. PFX export password (used to protect the output PFX)

**Certificate chain handling:**
- If the `.crt` file contains multiple PEM certificates, the tool treats the last certificate as the leaf and everything else as the chain.
- If the `.crt` contains only one certificate, chain certs can be provided separately via `--chain`.
- Both approaches can be combined.

**When to use `--legacy`:** Older systems like Windows Server 2012, Java 8, and some hardware appliances cannot read modern PFX files. The `--legacy` flag uses TripleDES-SHA1 encryption for compatibility.

### pfx-legacy

Convert an existing PFX to legacy TripleDES-SHA1 format.

```bash
ssl-toolbox pfx-legacy --input modern.pfx --out legacy.pfx
```

| Flag | Required | Description |
|---|---|---|
| `--input`, `-i` | Yes | Input PFX file path |
| `--out`, `-o` | Yes | Output legacy PFX file path |

Prompts for the input PFX password and a password for the output file. The input and output passwords can differ.

### view-cert

Display details of a certificate file.

```bash
ssl-toolbox view-cert --input server.crt
```

| Flag | Required | Description |
|---|---|---|
| `--input`, `-i` | Yes | Certificate file path (`.crt`, `.cer`, `.pem`, `.der`) |

Shows:
- Common Name, Issuer, Validity period
- Subject Alternative Names
- If the file contains a chain: certificates are displayed in the same order they appear in the file, with roles inferred from that order when possible

Accepts both PEM and DER encoded files.

### view-csr

Display details of a CSR file.

```bash
ssl-toolbox view-csr --input server.csr
```

| Flag | Required | Description |
|---|---|---|
| `--input`, `-i` | Yes | CSR file path |

Shows the Common Name and all SANs (DNS, IP, email, URI). Accepts PEM and DER formats.

### view-pfx

Display the certificates inside a PFX/PKCS12 file.

```bash
ssl-toolbox view-pfx --input server.pfx
```

| Flag | Required | Description |
|---|---|---|
| `--input`, `-i` | Yes | PFX file path |

Prompts for the PFX password, then displays all certificates (leaf, intermediates, root) with their details.

### verify-https

Verify the TLS certificate and connection for an HTTPS endpoint.

```bash
ssl-toolbox verify-https --host example.com
ssl-toolbox verify-https --host example.com --port 8443
ssl-toolbox verify-https --host example.com --no-verify
ssl-toolbox verify-https --host example.com --out verify-https.txt
```

| Flag | Required | Description |
|---|---|---|
| `--host`, `-H` | Yes | Hostname to connect to |
| `--port`, `-p` | No | Port number (default: 443) |
| `--no-verify` | No | Skip certificate validation (still shows cert details) |
| `--full-scan` | No | Probe each protocol version against the locally testable cipher-suite set |
| `--out`, `-o` | No | Save the verification report to a file |

**Output includes:**
- Negotiated protocol version and cipher suite
- TLS version support table (TLS 1.0, 1.1, 1.2, 1.3)
- Optional full protocol/cipher-suite scan with `--full-scan` for HTTPS and LDAPS across the locally testable cipher set
- Certificate validation: hostname match, expiry check, chain verification
- Full certificate chain with SANs

Connection timeout is 10 seconds for both TCP and TLS handshake.

**Hostname validation** follows RFC 6125:
- SANs are checked first; CN is only used as fallback when no DNS SANs exist
- Wildcard certificates (`*.example.com`) match one level of subdomain only

### verify-ldaps

Verify the TLS certificate for an LDAPS endpoint. Same behavior and flags as [verify-https](#verify-https).

```bash
ssl-toolbox verify-ldaps --host ldap.example.com
ssl-toolbox verify-ldaps --host ldap.example.com --port 3269
ssl-toolbox verify-ldaps --host ldap.example.com --out verify-ldaps.txt
```

| Flag | Required | Description |
|---|---|---|
| `--host`, `-H` | Yes | LDAP server hostname |
| `--port`, `-p` | No | Port number (default: 636) |
| `--no-verify` | No | Skip certificate validation |
| `--full-scan` | No | Probe each protocol version against the locally testable cipher-suite set |
| `--out`, `-o` | No | Save the verification report to a file |

### verify-smtp

Verify a TLS certificate via SMTP STARTTLS.

```bash
ssl-toolbox verify-smtp --host smtp.example.com
ssl-toolbox verify-smtp --host smtp.example.com --port 25
ssl-toolbox verify-smtp --host smtp.example.com --out verify-smtp.txt
```

| Flag | Required | Description |
|---|---|---|
| `--host`, `-H` | Yes | SMTP server hostname |
| `--port`, `-p` | No | Port number (default: 587) |
| `--no-verify` | No | Skip certificate validation |
| `--out`, `-o` | No | Save the verification report to a file |

Unlike `verify-https` and `verify-ldaps`, this command speaks the SMTP protocol: it connects on plaintext, sends EHLO, checks for STARTTLS support, and upgrades the connection before extracting TLS details.

### convert

Convert a certificate between formats.

```bash
ssl-toolbox convert --input cert.pem --output cert.der --format der
ssl-toolbox convert --input cert.der --output cert.pem --format pem
ssl-toolbox convert --input cert.pem --output cert.b64 --format base64
```

| Flag | Required | Description |
|---|---|---|
| `--input`, `-i` | Yes | Input certificate file |
| `--output`, `-o` | Yes | Output file path |
| `--format`, `-f` | Yes | Target format: `pem`, `der`, or `base64` |

**Conversion directions:**

| Input | Target | Notes |
|---|---|---|
| PEM | DER | Strips headers, decodes base64 to binary ASN.1 |
| DER | PEM | Encodes binary to base64 with `-----BEGIN/END CERTIFICATE-----` headers |
| PEM | Base64 | Raw base64 with no PEM headers (line-wrapped at 76 characters) |

### identify

Auto-detect the format of a certificate file.

```bash
ssl-toolbox identify --input somefile.crt
```

| Flag | Required | Description |
|---|---|---|
| `--input`, `-i` | Yes | File to identify |

Prints one of: PEM, DER, PKCS12/PFX, Base64, or Unknown.

Detection works by checking for PEM headers, attempting DER and PKCS12 parsing, and falling back to base64 heuristics.

### ca list-profiles

List available certificate types from Sectigo. *(Requires `sectigo` feature.)*

```bash
ssl-toolbox ca list-profiles
```

Authenticates with Sectigo using your OAuth credentials, fetches available SSL certificate types for your organization, and displays each profile's name, ID, and available validity terms.

### ca submit

Submit a CSR to Sectigo for signing. *(Requires `sectigo` feature.)*

```bash
ssl-toolbox ca submit --csr server.csr --out signed.crt
ssl-toolbox ca submit --csr server.csr --out signed.crt --description "Production cert"
ssl-toolbox ca submit --csr server.csr --out signed.crt --product-code 4491
```

| Flag | Required | Description |
|---|---|---|
| `--csr`, `-c` | Yes | Path to CSR file |
| `--out`, `-o` | Yes | Output path for signed certificate |
| `--description`, `-d` | No | Comment/description attached to the certificate order |
| `--product-code`, `-p` | No | Sectigo certificate type ID (uses config default if omitted) |

**Behavior:**
1. Displays CSR details (CN, SANs) for review
2. Authenticates with Sectigo OAuth
3. Submits CSR with the selected product code and maximum available term
4. Waits 20 seconds for certificate processing
5. Downloads the signed certificate in PEM format
6. Displays the certificate details and saves to the output path

If `--product-code` is not set and `SECTIGO_PRODUCT_CODE` is not in the environment or config, the interactive menu will prompt you to select from available profiles.

### ca collect

Download a signed certificate by its request ID. *(Requires `sectigo` feature.)*

```bash
ssl-toolbox ca collect --id 12345 --out cert.crt
ssl-toolbox ca collect --id 12345 --out cert.crt --format chain
```

| Flag | Required | Description |
|---|---|---|
| `--id`, `-i` | Yes | Sectigo SSL request ID |
| `--out`, `-o` | Yes | Output file path |
| `--format`, `-f` | No | Download format: `pem` (default), `chain`, or `pkcs7` |

| Format | Sectigo API value | Contents |
|---|---|---|
| `pem` | `x509` | End-entity certificate only |
| `chain` | `x509CO` | Certificate + intermediate chain |
| `pkcs7` | `pkcs7` | PKCS#7 bundle |

---

## Configuration In Depth

### Config File Locations

ssl-toolbox searches two directories for JSON config files:

| Location | Scope | Created by |
|---|---|---|
| `~/.ssl-toolbox/` | User-level (all projects) | `ssl-toolbox init --global` |
| `./.ssl-toolbox/` | Project-level (current directory) | `ssl-toolbox init` |

Both directories are optional. If neither exists, all values default to empty strings and prompts will have no prefilled defaults.

### config.json Reference

Controls default values for interactive CSR prompts (`new-config` command and interactive menu option 3).

```json
{
  "country": "US",
  "state": "Texas",
  "locality": "Dallas",
  "organization": "Acme Corp",
  "org_unit": "Engineering",
  "email": "certs@acme.com"
}
```

| Field | Type | Description |
|---|---|---|
| `country` | String | Two-letter ISO country code |
| `state` | String | State or province name |
| `locality` | String | City or locality |
| `organization` | String | Legal organization name |
| `org_unit` | String | Organizational unit / department |
| `email` | String | Contact email address |

All fields are optional. Omitted or empty fields result in prompts with no default value (the user must type a value).

### sectigo.json Reference

Configures the Sectigo CA plugin. Only needed when using `ca` subcommands.

```json
{
  "api_base": "https://admin.enterprise.sectigo.com",
  "org_id": "12345",
  "product_code": "4491",
  "token_url": "https://auth.sso.sectigo.com/auth/realms/apiclients/protocol/openid-connect/token"
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `api_base` | String | `https://admin.enterprise.sectigo.com` | Sectigo Certificate Manager API base URL |
| `org_id` | String | *(empty)* | Your Sectigo organization ID |
| `product_code` | String | *(empty)* | Default certificate type/profile ID |
| `token_url` | String | *(empty)* | OAuth 2.0 token endpoint URL |

### Environment Variables

Environment variables override config file values. Secrets (OAuth credentials) should only be set via environment variables or `.env` files -- never in JSON config.

| Variable | Overrides | Description |
|---|---|---|
| `SCM_CLIENT_ID` | *(secret, .env only)* | Sectigo OAuth client ID |
| `SCM_CLIENT_SECRET` | *(secret, .env only)* | Sectigo OAuth client secret |
| `SCM_TOKEN_URL` | `sectigo.json` `token_url` | OAuth token endpoint |
| `SECTIGO_API_BASE` | `sectigo.json` `api_base` | Sectigo API base URL |
| `SECTIGO_ORG_ID` | `sectigo.json` `org_id` | Sectigo organization ID |
| `SECTIGO_PRODUCT_CODE` | `sectigo.json` `product_code` | Default certificate type ID |

The tool loads `.env` files automatically from the current directory using `dotenvy`.

### Layering and Precedence

When the same value is defined in multiple places, the last one wins:

```
Compiled defaults (empty strings)
  < ~/.ssl-toolbox/config.json
    < ./.ssl-toolbox/config.json
      < Environment variables / .env
        < CLI flags
```

**Example:** If `~/.ssl-toolbox/config.json` sets `"state": "Texas"` but `./.ssl-toolbox/config.json` sets `"state": "California"`, the prompt will default to `California`.

**Merging rule for config files:** Only non-empty fields from a higher-priority file override lower-priority values. An empty string in a project-level config does **not** clear a user-level default.

---

## Workflows

### Workflow: Generate a CSR and Key

**Step 1:** Create an OpenSSL config file interactively:

```bash
ssl-toolbox new-config --out myserver.cnf
```

Fill in the prompts. The tool generates a complete OpenSSL config with your subject, SANs, key size, and extended key usage.

**Step 2:** Generate the key and CSR:

```bash
ssl-toolbox generate --conf myserver.cnf --key myserver.key --csr myserver.csr
```

You will be prompted for a password to encrypt the private key (AES-256-CBC).

**Step 3:** Submit the CSR to your CA for signing, or use the Sectigo integration (see below).

### Workflow: Submit to Sectigo and Create PFX

**Prerequisites:** Configure Sectigo credentials in `.env` and settings in `.ssl-toolbox/sectigo.json`.

```bash
# Submit CSR and download signed certificate
ssl-toolbox ca submit --csr myserver.csr --out myserver.crt --description "Production web server"

# Create PFX for deployment
ssl-toolbox pfx --key myserver.key --cert myserver.crt --out myserver.pfx
```

If the signed `.crt` contains a full chain (common with Sectigo), the tool automatically extracts the leaf cert and includes intermediates in the PFX.

### Workflow: Verify a TLS Endpoint

```bash
# Quick check
ssl-toolbox verify-https --host www.example.com

# LDAPS server on non-standard port
ssl-toolbox verify-ldaps --host ldap.corp.local --port 3269

# SMTP with STARTTLS
ssl-toolbox verify-smtp --host mail.example.com

# Self-signed or internal CA (skip validation, still shows cert info)
ssl-toolbox verify-https --host internal.corp.local --no-verify
```

The output shows:
- Negotiated cipher suite and protocol
- Which TLS versions the server supports (1.0 through 1.3)
- Whether the hostname matches the certificate
- Whether the certificate is expired
- Whether the chain verifies against the system trust store

### Workflow: Convert Certificate Formats

```bash
# PEM to DER (for systems that need binary format)
ssl-toolbox convert --input cert.pem --output cert.der --format der

# DER back to PEM
ssl-toolbox convert --input cert.der --output cert.pem --format pem

# PEM to raw Base64 (no headers, line-wrapped at 76 chars)
ssl-toolbox convert --input cert.pem --output cert.b64 --format base64

# Not sure what format a file is?
ssl-toolbox identify --input mystery.crt
```

### Workflow: Migrate a PFX to Legacy Format

Some older systems (Windows Server 2012, Java 8, certain hardware load balancers) cannot read PFX files created with modern AES-256 encryption.

```bash
# Convert an existing modern PFX to legacy TripleDES-SHA1
ssl-toolbox pfx-legacy --input modern.pfx --out legacy.pfx
```

Or create a legacy PFX directly from key + cert:

```bash
ssl-toolbox pfx --key server.key --cert server.crt --out legacy.pfx --legacy
```

---

## OpenSSL Config File Format

The `generate` command reads OpenSSL-style `.cnf` files. The `new-config` and `config` commands produce them. Here is the full format:

```ini
[ req ]
default_bits        = 2048
default_md          = sha256
string_mask         = utf8only
distinguished_name  = req_distinguished_name
req_extensions      = v3_req
prompt              = no

[ req_distinguished_name ]
countryName             = US
stateOrProvinceName     = Texas
localityName            = Dallas
organizationName        = Acme Corp
organizationalUnitName  = Engineering
commonName              = app.example.com
emailAddress            = certs@acme.com

[ v3_req ]
basicConstraints        = CA:FALSE
keyUsage                = critical, digitalSignature, keyEncipherment
extendedKeyUsage        = serverAuth
subjectKeyIdentifier    = hash
subjectAltName          = @alt_names

[ alt_names ]
DNS.1 = app.example.com
DNS.2 = www.example.com
DNS.3 = api.example.com
IP.1 = 10.0.1.50
```

**Supported sections:**

| Section | Purpose |
|---|---|
| `[req]` | Request options (bits, digest, extensions) |
| `[req_distinguished_name]` | Subject fields |
| `[v3_req]` | X.509v3 extensions (key usage, SANs) |
| `[alt_names]` | Subject Alternative Names |

**Supported distinguished name fields:**

| Short | Long | Description |
|---|---|---|
| `C` | `countryName` | 2-letter country code |
| `ST` | `stateOrProvinceName` | State or province |
| `L` | `localityName` | City or locality |
| `O` | `organizationName` | Organization |
| `OU` | `organizationalUnitName` | Organizational unit |
| `CN` | `commonName` | Common name (FQDN) |
| | `emailAddress` | Contact email |

**Supported SAN types:**

| Prefix | Example | Description |
|---|---|---|
| `DNS.N` | `DNS.1 = example.com` | DNS hostname |
| `IP.N` | `IP.1 = 10.0.1.50` | IP address (v4 or v6) |
| `email.N` | `email.1 = admin@example.com` | Email address |
| `URI.N` | `URI.1 = https://example.com` | URI |

**Extended Key Usage options:**

| Value | Use case |
|---|---|
| `serverAuth` | TLS server certificates (most common) |
| `clientAuth` | TLS client certificates |
| `serverAuth, clientAuth` | Mutual TLS (mTLS) |

---

## Certificate Formats

| Format | Extension(s) | Description |
|---|---|---|
| **PEM** | `.pem`, `.crt`, `.cer`, `.key` | Base64-encoded with `-----BEGIN/END-----` headers. Human-readable. Most common on Linux. |
| **DER** | `.der`, `.cer` | Raw binary ASN.1 encoding. Used by Java and some Windows tools. |
| **PFX/PKCS12** | `.pfx`, `.p12` | Binary container holding a private key, certificate, and optional chain. Password-protected. Used for deployment. |
| **Base64** | `.b64` | Raw base64 without PEM headers. Occasionally used for embedding in JSON/XML. |
| **PKCS7** | `.p7b`, `.p7c` | Certificate-only container (no private key). Sometimes used by CAs for chain delivery. |

---

## Troubleshooting

### "Private key is encrypted but no password was provided"

The private key file is AES-encrypted. Enter the password you used when generating the key. If the key is not encrypted, press Enter at the prompt.

### "Key values mismatch"

The private key and certificate don't correspond to each other. Verify you're using the correct key for the certificate. This often happens when the wrong `.crt` file is selected (e.g., an intermediate instead of the leaf).

### "SCM_CLIENT_ID not set"

The Sectigo CA commands require OAuth credentials. Create a `.env` file:

```env
SCM_CLIENT_ID=your_client_id
SCM_CLIENT_SECRET=your_client_secret
```

### "SCM_TOKEN_URL not set"

Set the token URL either in `.env` or in `.ssl-toolbox/sectigo.json`:

```json
{
  "token_url": "https://auth.sso.sectigo.com/auth/realms/apiclients/protocol/openid-connect/token"
}
```

### "No CA plugin compiled"

You built the binary with `--no-default-features`. Rebuild with the Sectigo feature:

```bash
cargo build --release -p ssl-toolbox
```

### Certificate chain issues with PFX

When a `.crt` file contains multiple certificates (chain), the tool uses the **last** certificate in the file as the leaf. If your chain order has the leaf first, this may select the wrong certificate. Ensure chain files are ordered with intermediates first and the leaf last, or provide the chain separately:

```bash
ssl-toolbox pfx --key server.key --cert leaf-only.crt --out server.pfx --chain intermediates.crt
```

### TLS verification shows "chain verification failed"

The server's certificate chain could not be verified against your system's trust store. Common causes:

- Self-signed certificate -- use `--no-verify` to skip validation and still see cert details
- Missing intermediate certificates on the server
- Internal/private CA not in the system trust store
- Expired root or intermediate certificate

### Connection timeout during TLS verification

The tool uses a 10-second timeout for both TCP connection and TLS handshake. If the server is unreachable or a firewall blocks the port, the connection will time out. Verify network connectivity and port access.

### Debug output

Add `--debug` to any command for verbose output including HTTP request/response details, TLS negotiation info, and internal state:

```bash
ssl-toolbox --debug verify-https --host example.com
ssl-toolbox --debug ca submit --csr server.csr --out signed.crt
```

# ssl-toolbox

A Rust-based command-line tool for managing SSL/TLS certificates. Supports generating keys and CSRs, creating PFX/PKCS12 files, verifying TLS endpoints, converting certificate formats, and optionally integrating with the Sectigo Certificate Manager API.

## Features

- **Generate Keys and CSRs** - Create RSA private keys and certificate signing requests
- **PFX Creation** - Combine private keys and certificates into PFX/PKCS12 files (modern and legacy TripleDES-SHA1)
- **Certificate Viewing** - Inspect certificates, CSRs, and PFX files
- **TLS Verification** - Check HTTPS, LDAPS, and SMTP STARTTLS endpoints
- **Format Conversion** - Convert between PEM, DER, and Base64
- **Format Detection** - Auto-identify certificate file formats
- **Config Generation** - Build OpenSSL config files from scratch or from existing certs/CSRs
- **CA Integration** - Submit CSRs to Sectigo Certificate Manager and retrieve signed certificates (optional, feature-gated)

## Prerequisites

- Rust 1.85+ (edition 2024)

## Installation

### Build from Source

```bash
cargo build --release
```

The compiled binary will be available at `target/release/ssl-toolbox`.

To build without Sectigo CA support:

```bash
cargo build --release -p ssl-toolbox --no-default-features
```

## Configuration

ssl-toolbox uses a layered config system. Values are resolved in order (later wins):

1. Compiled defaults (empty strings)
2. `~/.ssl-toolbox/` (user-level defaults)
3. `./.ssl-toolbox/` (project-level overrides)
4. Environment variables / `.env` file
5. CLI flags

### Quick Start

```bash
# Generate config files in the current directory
ssl-toolbox init

# Or generate global config files in ~/.ssl-toolbox/
ssl-toolbox init --global
```

This creates two files:

**`.ssl-toolbox/config.json`** - CSR profile defaults:

```json
{
  "country": "US",
  "state": "",
  "locality": "",
  "organization": "",
  "org_unit": "",
  "email": ""
}
```

**`.ssl-toolbox/sectigo.json`** - Sectigo plugin config (only needed if using CA features):

```json
{
  "api_base": "https://cert-manager.com",
  "org_id": "",
  "product_code": "",
  "token_url": ""
}
```

### Sectigo Credentials

Secrets must be stored in a `.env` file (never in JSON config files):

```env
SCM_CLIENT_ID=<your client id>
SCM_CLIENT_SECRET=<your client secret>
```

## Usage

### Interactive Mode

Run without arguments to enter interactive mode:

```bash
ssl-toolbox
```

### Command-Line Mode

#### Initialize Config

```bash
ssl-toolbox init            # project-level .ssl-toolbox/
ssl-toolbox init --global   # user-level ~/.ssl-toolbox/
```

#### Generate Key and CSR

```bash
ssl-toolbox generate \
  --conf openssl.conf \
  --key output.key \
  --csr output.csr \
  --password <key-password>
```

#### Generate New OpenSSL Config

```bash
ssl-toolbox new-config --out server.cnf
```

#### Generate Config from Existing Certificate

```bash
ssl-toolbox config \
  --input certificate.crt \
  --out openssl.conf \
  --is-csr  # include if input is a CSR instead of certificate
```

#### Create PFX File

```bash
ssl-toolbox pfx \
  --key output.key \
  --cert signed.crt \
  --out certificate.pfx \
  --chain chain.crt    # optional
  --legacy             # optional: use TripleDES-SHA1
```

#### Convert Legacy PFX

```bash
ssl-toolbox pfx-legacy --input modern.pfx --out legacy.pfx
```

#### View Certificate / CSR / PFX Details

```bash
ssl-toolbox view-cert --input certificate.crt
ssl-toolbox view-csr --input request.csr
ssl-toolbox view-pfx --input certificate.pfx
```

#### Convert Certificate Format

```bash
ssl-toolbox convert --input cert.pem --output cert.der --format der
ssl-toolbox convert --input cert.der --output cert.pem --format pem
ssl-toolbox convert --input cert.pem --output cert.b64 --format base64
```

#### Identify Certificate Format

```bash
ssl-toolbox identify --input certificate.crt
```

#### Verify TLS Endpoints

```bash
ssl-toolbox verify-https --host example.com --port 443
ssl-toolbox verify-ldaps --host ldap.example.com --port 636
ssl-toolbox verify-smtp --host smtp.example.com --port 587
```

#### CA Operations (requires Sectigo feature)

```bash
ssl-toolbox ca list-profiles
ssl-toolbox ca submit --csr request.csr --out signed.crt --description "Production cert"
ssl-toolbox ca collect --id 12345 --out cert.crt --format pem
```

## OpenSSL Configuration Format

The tool expects OpenSSL configuration files with the following structure:

```ini
[ req ]

[ req_distinguished_name ]
C = US
ST = Your State
L = Your City
O = Your Organization
OU = IT Department
CN = example.com

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = example.com
DNS.2 = www.example.com
IP.1 = 192.168.1.1
```

## Complete Workflow Example

```bash
# 1. Initialize config with your org defaults
ssl-toolbox init
# Edit .ssl-toolbox/config.json with your organization info

# 2. Generate key and CSR (prompts will use your configured defaults)
ssl-toolbox new-config --out config/server.cnf
ssl-toolbox generate \
  --conf config/server.cnf \
  --key data/server.key \
  --csr data/server.csr

# 3. Submit to Sectigo and get signed certificate
ssl-toolbox ca submit \
  --csr data/server.csr \
  --out data/server.crt \
  --description "Production web server certificate"

# 4. Create PFX for deployment
ssl-toolbox pfx \
  --key data/server.key \
  --cert data/server.crt \
  --out data/server.pfx
```

## Troubleshooting

### "Private key is encrypted but no password was provided"
- Ensure you enter the correct password when prompted for the private key password
- If your key is not encrypted, simply press Enter when prompted

### "Key values mismatch" error
- Verify that the certificate and private key match
- Check that you're using the correct certificate (end-entity, not intermediate/root)

### Certificate chain issues
- The tool automatically handles multi-certificate files
- Ensure your `.crt` file contains the full chain if not providing a separate `--chain` file

## Development

### Build

```bash
cargo build
```

### Type Check

```bash
cargo check --workspace
cargo check -p ssl-toolbox --no-default-features  # verify sans-Sectigo build
```

### Run with Debug Output

```bash
ssl-toolbox --debug
```

## License

MIT OR Apache-2.0

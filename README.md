# Cert Gen Tools

A Rust-based command-line tool for managing SSL/TLS certificates with the Sectigo Certificate Manager API. This tool streamlines the process of generating keys, creating certificate signing requests (CSRs), submitting them to Sectigo, and creating PFX/PKCS12 files.

## Features

- **Generate Keys and CSRs** - Create RSA private keys and certificate signing requests from OpenSSL configuration files
- **Sectigo API Integration** - Automatically submit CSRs to Sectigo Certificate Manager and retrieve signed certificates
- **PFX Creation** - Combine private keys and certificates into PFX/PKCS12 files for easy deployment
- **Config Generation** - Extract configuration from existing certificates or CSRs for reuse
- **Interactive & CLI Modes** - Use the interactive menu or command-line arguments for automation

## Prerequisites

- Rust 1.70 or later
- Sectigo Certificate Manager API credentials (Client ID and Secret)

## Installation

### Build from Source

```bash
cargo build --release
```

The compiled binary will be available at `target/release/cert-gen-tools`.

## Configuration

Create a `.env` file in the project root with your Sectigo API credentials:

```env
# Sectigo Certificate Manager API Configuration
SECTIGO_API_BASE=https://cert-manager.com
SECTIGO_ORG_ID=your_org_id
SECTIGO_PRODUCT_CODE=your_product_code
SECTIGO_TERM=190

# Sectigo SCM OAuth Credentials
SCM_CLIENT_ID=your_client_id
SCM_CLIENT_SECRET=your_client_secret
SCM_TOKEN_URL=https://your-tenant.us.idaptive.app/oauth2/token/your_app_id
```

## Usage

### Interactive Mode

Run without arguments to enter interactive mode:

```bash
cert-gen-tools
```

You'll be presented with a menu to:
1. Generate Key and CSR
2. Submit CSR to Sectigo
3. Create PFX
4. Generate Config from Cert/CSR

### Command-Line Mode

#### Generate Key and CSR

```bash
cert-gen-tools generate \
  --conf openssl.conf \
  --key output.key \
  --csr output.csr \
  --password <key-password>
```

#### Submit CSR to Sectigo

```bash
cert-gen-tools submit \
  --csr output.csr \
  --out signed.crt \
  --description "Certificate for production server"
```

#### Create PFX File

```bash
cert-gen-tools pfx \
  --key output.key \
  --cert signed.crt \
  --out certificate.pfx \
  --chain chain.crt  # optional
```

**Note:** When creating a PFX, you'll be prompted for:
1. Private key password (if encrypted, or press Enter if not encrypted)
2. PFX export password (password for the output PFX file)
3. PEM pass phrase (from OpenSSL - enter the same password as #2)

#### Generate Config from Certificate

```bash
cert-gen-tools config \
  --input certificate.crt \
  --out openssl.conf \
  --is-csr  # include if input is a CSR instead of certificate
```

## OpenSSL Configuration Format

The tool expects OpenSSL configuration files with the following structure:

```ini
[ req ]

[ req_distinguished_name ]
C = US
ST = Texas
L = Dallas
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

## Certificate Chain Handling

The tool automatically handles certificate files containing full chains:
- When a `.crt` file contains multiple certificates (e.g., end-entity + intermediates + root), the tool automatically extracts the end-entity certificate
- Intermediate and root certificates are included in the PFX chain automatically
- You can also provide a separate chain file using the `--chain` option

## Examples

### Complete Workflow

```bash
# 1. Generate key and CSR
cert-gen-tools generate \
  --conf config/server.conf \
  --key data/server.key \
  --csr data/server.csr

# 2. Submit to Sectigo and get signed certificate
cert-gen-tools submit \
  --csr data/server.csr \
  --out data/server.crt \
  --description "Production web server certificate"

# 3. Create PFX for deployment
cert-gen-tools pfx \
  --key data/server.key \
  --cert data/server.crt \
  --out data/server.pfx
```

### Extract Config from Existing Certificate

```bash
cert-gen-tools config \
  --input existing-cert.crt \
  --out extracted.conf
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

### Run Tests

```bash
cargo test
```

### Run with Debug Output

```bash
RUST_LOG=debug cargo run
```

## License

Internal use only - Baylor Scott & White Health
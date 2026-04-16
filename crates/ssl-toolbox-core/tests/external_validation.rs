use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use ssl_toolbox_core::CertFormat;
use ssl_toolbox_core::convert::{der_to_pem, detect_format, pem_to_base64, pem_to_der};
use ssl_toolbox_core::key_csr::{extract_csr_details, generate_key_and_csr};
use ssl_toolbox_core::pfx::{
    create_pfx, create_pfx_legacy, create_pfx_legacy_3des, extract_pfx_details,
};
use ssl_toolbox_core::x509_utils::extract_cert_chain_details;

#[test]
fn generated_csr_is_accepted_by_openssl_and_matches_private_key() -> Result<(), Box<dyn Error>> {
    if !command_exists("openssl") {
        eprintln!("Skipping external validation test because `openssl` is unavailable.");
        return Ok(());
    }

    let temp = TestDir::new("ssl-toolbox-csr-validation")?;
    let config = temp.path("openssl.cnf");
    let key = temp.path("server.key");
    let csr = temp.path("server.csr");
    let key_password = "changeit-key";

    fs::write(
        &config,
        r#"[req_distinguished_name]
C = US
ST = Texas
L = Austin
O = SSL Toolbox
OU = Platform
CN = svc.example.test
emailAddress = certs@example.test

[alt_names]
DNS.1 = svc.example.test
DNS.2 = api.example.test
IP.1 = 127.0.0.1
email.1 = certs@example.test
URI.1 = spiffe://example.test/service
"#,
    )?;

    generate_key_and_csr(
        path_str(&config)?,
        path_str(&key)?,
        path_str(&csr)?,
        key_password,
    )?;

    let (common_name, sans) = extract_csr_details(path_str(&csr)?)?;
    assert_eq!(common_name, "svc.example.test");
    assert_eq!(
        sans,
        vec![
            "DNS: svc.example.test".to_string(),
            "DNS: api.example.test".to_string(),
            "IP: 127.0.0.1".to_string(),
            "Email: certs@example.test".to_string(),
            "URI: spiffe://example.test/service".to_string(),
        ]
    );

    let verify = run_command(
        "openssl",
        &["req", "-in", path_str(&csr)?, "-noout", "-verify", "-text"],
    )?;
    assert!(
        normalize_openssl_subject(&verify.stdout).contains("Subject: C=US, ST=Texas, L=Austin, O=SSL Toolbox, OU=Platform, CN=svc.example.test, emailAddress=certs@example.test"),
        "unexpected openssl CSR text:\n{}",
        verify.stdout
    );
    assert!(
        verify.stdout.contains("DNS:svc.example.test")
            && verify.stdout.contains("DNS:api.example.test")
            && verify.stdout.contains("IP Address:127.0.0.1")
            && verify.stdout.contains("email:certs@example.test")
            && verify.stdout.contains("URI:spiffe://example.test/service"),
        "missing expected SANs in openssl CSR text:\n{}",
        verify.stdout
    );
    assert!(
        verify.stderr.contains("verify OK") || verify.stdout.contains("verify OK"),
        "openssl did not verify CSR signature:\nstdout:\n{}\nstderr:\n{}",
        verify.stdout,
        verify.stderr
    );

    let subject = run_command(
        "openssl",
        &[
            "req",
            "-in",
            path_str(&csr)?,
            "-noout",
            "-subject",
            "-nameopt",
            "RFC2253",
        ],
    )?;
    assert!(
        subject.stdout.contains("CN=svc.example.test")
            && subject.stdout.contains("OU=Platform")
            && subject.stdout.contains("O=SSL Toolbox")
            && subject.stdout.contains("L=Austin")
            && subject.stdout.contains("ST=Texas")
            && subject.stdout.contains("C=US"),
        "unexpected openssl CSR subject:\n{}",
        subject.stdout
    );

    let csr_pubkey = run_command(
        "openssl",
        &["req", "-in", path_str(&csr)?, "-pubkey", "-noout"],
    )?;
    let key_pubkey = run_command(
        "openssl",
        &[
            "pkey",
            "-in",
            path_str(&key)?,
            "-passin",
            &format!("pass:{key_password}"),
            "-pubout",
        ],
    )?;
    assert_eq!(
        normalize_pem(&csr_pubkey.stdout),
        normalize_pem(&key_pubkey.stdout),
        "public key extracted from CSR does not match the generated private key"
    );

    Ok(())
}

#[test]
fn pfx_outputs_are_accepted_by_openssl_and_keytool() -> Result<(), Box<dyn Error>> {
    if !command_exists("openssl") || !command_exists("keytool") {
        eprintln!(
            "Skipping external validation test because `openssl` or `keytool` is unavailable."
        );
        return Ok(());
    }

    let temp = TestDir::new("ssl-toolbox-pfx-validation")?;
    let materials = create_signed_materials(&temp)?;
    let pfx = temp.path("server.pfx");
    let pfx_password = "changeit-pfx";

    create_pfx(
        path_str(&materials.key)?,
        path_str(&materials.leaf_cert)?,
        Some(path_str(&materials.root_cert)?),
        path_str(&pfx)?,
        Some(&materials.key_password),
        pfx_password,
    )?;

    let details = extract_pfx_details(&fs::read(&pfx)?, pfx_password)?;
    assert_eq!(details.len(), 2);
    assert_eq!(details[0].common_name, "svc.example.test");
    assert_eq!(details[1].common_name, "SSL Toolbox Test Root CA");
    assert_eq!(details[0].public_key_bits, 2048);
    assert_eq!(details[0].signature_algorithm, "sha256WithRSAEncryption");
    assert!(!details[0].serial_number.is_empty());
    assert!(details[0].sha1_fingerprint.contains(':'));
    assert!(details[0].sha256_fingerprint.contains(':'));
    assert_eq!(detect_format(&fs::read(&pfx)?), CertFormat::Pkcs12);

    let openssl_leaf = run_command(
        "openssl",
        &[
            "pkcs12",
            "-in",
            path_str(&pfx)?,
            "-passin",
            &format!("pass:{pfx_password}"),
            "-clcerts",
            "-nokeys",
        ],
    )?;
    let openssl_leaf_details = extract_cert_chain_details(openssl_leaf.stdout.as_bytes())?;
    assert_eq!(openssl_leaf_details.len(), 1);
    assert_eq!(openssl_leaf_details[0].common_name, "svc.example.test");

    let openssl_chain = run_command(
        "openssl",
        &[
            "pkcs12",
            "-in",
            path_str(&pfx)?,
            "-passin",
            &format!("pass:{pfx_password}"),
            "-cacerts",
            "-nokeys",
        ],
    )?;
    let openssl_chain_details = extract_cert_chain_details(openssl_chain.stdout.as_bytes())?;
    assert_eq!(openssl_chain_details.len(), 1);
    assert_eq!(
        openssl_chain_details[0].common_name,
        "SSL Toolbox Test Root CA"
    );

    let keytool = run_command(
        "keytool",
        &[
            "-list",
            "-v",
            "-storetype",
            "PKCS12",
            "-keystore",
            path_str(&pfx)?,
            "-storepass",
            pfx_password,
        ],
    )?;
    assert!(
        keytool.stdout.contains("PrivateKeyEntry"),
        "unexpected keytool output:\n{}",
        keytool.stdout
    );
    assert!(
        keytool.stdout.contains("Certificate chain length: 2"),
        "keytool did not report the expected chain length:\n{}",
        keytool.stdout
    );
    assert!(
        keytool.stdout.contains("CN=svc.example.test")
            && keytool.stdout.contains("CN=SSL Toolbox Test Root CA"),
        "keytool output did not contain the expected subject chain:\n{}",
        keytool.stdout
    );

    Ok(())
}

#[test]
fn legacy_pfx_and_converted_formats_round_trip_through_external_tools() -> Result<(), Box<dyn Error>>
{
    if !command_exists("openssl") || !command_exists("keytool") {
        eprintln!(
            "Skipping external validation test because `openssl` or `keytool` is unavailable."
        );
        return Ok(());
    }

    let temp = TestDir::new("ssl-toolbox-legacy-validation")?;
    let materials = create_signed_materials(&temp)?;
    let pfx_password = "changeit-pfx";
    let standard_pfx = temp.path("standard.pfx");
    let legacy_from_existing = temp.path("legacy-from-existing.pfx");
    let legacy_from_bundle = temp.path("legacy-from-bundle.pfx");
    let der = temp.path("server.der");
    let pem_round_trip = temp.path("server-roundtrip.pem");
    let base64 = temp.path("server.b64");
    let base64_pem = temp.path("server-base64.pem");

    create_pfx(
        path_str(&materials.key)?,
        path_str(&materials.leaf_cert)?,
        Some(path_str(&materials.root_cert)?),
        path_str(&standard_pfx)?,
        Some(&materials.key_password),
        pfx_password,
    )?;

    create_pfx_legacy_3des(
        &fs::read(&standard_pfx)?,
        pfx_password,
        path_str(&legacy_from_existing)?,
        pfx_password,
    )?;
    create_pfx_legacy(
        path_str(&materials.key)?,
        path_str(&materials.bundle_cert)?,
        None,
        path_str(&legacy_from_bundle)?,
        Some(&materials.key_password),
        pfx_password,
    )?;

    validate_legacy_pfx(&legacy_from_existing, pfx_password)?;
    validate_legacy_pfx(&legacy_from_bundle, pfx_password)?;

    pem_to_der(path_str(&materials.leaf_cert)?, path_str(&der)?)?;
    der_to_pem(path_str(&der)?, path_str(&pem_round_trip)?)?;
    pem_to_base64(path_str(&materials.leaf_cert)?, path_str(&base64)?)?;

    assert_eq!(detect_format(&fs::read(&der)?), CertFormat::Der);
    assert_eq!(detect_format(&fs::read(&pem_round_trip)?), CertFormat::Pem);

    let base64_text = fs::read_to_string(&base64)?;
    assert_eq!(detect_format(base64_text.as_bytes()), CertFormat::Base64);
    fs::write(
        &base64_pem,
        format!(
            "-----BEGIN CERTIFICATE-----\n{}-----END CERTIFICATE-----\n",
            base64_text
        ),
    )?;

    let der_subject = run_command(
        "openssl",
        &[
            "x509",
            "-in",
            path_str(&der)?,
            "-inform",
            "DER",
            "-noout",
            "-subject",
        ],
    )?;
    let pem_subject = run_command(
        "openssl",
        &[
            "x509",
            "-in",
            path_str(&pem_round_trip)?,
            "-noout",
            "-subject",
        ],
    )?;
    let base64_subject = run_command(
        "openssl",
        &["x509", "-in", path_str(&base64_pem)?, "-noout", "-subject"],
    )?;

    for output in [
        &der_subject.stdout,
        &pem_subject.stdout,
        &base64_subject.stdout,
    ] {
        assert!(
            normalize_openssl_subject(output).contains("CN=svc.example.test"),
            "unexpected openssl certificate subject output:\n{}",
            output
        );
    }

    Ok(())
}

struct SignedMaterials {
    key: PathBuf,
    leaf_cert: PathBuf,
    root_cert: PathBuf,
    bundle_cert: PathBuf,
    key_password: String,
}

fn create_signed_materials(temp: &TestDir) -> Result<SignedMaterials, Box<dyn Error>> {
    let config = temp.path("openssl.cnf");
    let key = temp.path("server.key");
    let csr = temp.path("server.csr");
    let root_key = temp.path("root.key");
    let root_cert = temp.path("root.crt");
    let root_serial = temp.path("root.srl");
    let leaf_cert = temp.path("server.crt");
    let bundle_cert = temp.path("bundle.crt");
    let key_password = "changeit-key".to_string();

    fs::write(
        &config,
        r#"[req_distinguished_name]
C = US
ST = Texas
L = Austin
O = SSL Toolbox
OU = Platform
CN = svc.example.test
emailAddress = certs@example.test

[alt_names]
DNS.1 = svc.example.test
DNS.2 = api.example.test
IP.1 = 127.0.0.1
email.1 = certs@example.test
URI.1 = spiffe://example.test/service
"#,
    )?;

    generate_key_and_csr(
        path_str(&config)?,
        path_str(&key)?,
        path_str(&csr)?,
        &key_password,
    )?;

    run_command(
        "openssl",
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            path_str(&root_key)?,
            "-out",
            path_str(&root_cert)?,
            "-days",
            "7",
            "-subj",
            "/C=US/ST=Texas/L=Austin/O=SSL Toolbox/CN=SSL Toolbox Test Root CA",
        ],
    )?;

    run_command(
        "openssl",
        &[
            "x509",
            "-req",
            "-in",
            path_str(&csr)?,
            "-CA",
            path_str(&root_cert)?,
            "-CAkey",
            path_str(&root_key)?,
            "-CAserial",
            path_str(&root_serial)?,
            "-CAcreateserial",
            "-out",
            path_str(&leaf_cert)?,
            "-days",
            "7",
            "-sha256",
            "-copy_extensions",
            "copy",
        ],
    )?;

    let root_pem = fs::read_to_string(&root_cert)?;
    let leaf_pem = fs::read_to_string(&leaf_cert)?;
    fs::write(&bundle_cert, format!("{root_pem}{leaf_pem}"))?;

    Ok(SignedMaterials {
        key,
        leaf_cert,
        root_cert,
        bundle_cert,
        key_password,
    })
}

fn validate_legacy_pfx(path: &Path, password: &str) -> Result<(), Box<dyn Error>> {
    let openssl_leaf = run_command(
        "openssl",
        &[
            "pkcs12",
            "-legacy",
            "-in",
            path_str(path)?,
            "-passin",
            &format!("pass:{password}"),
            "-clcerts",
            "-nokeys",
        ],
    )?;
    let openssl_chain = run_command(
        "openssl",
        &[
            "pkcs12",
            "-legacy",
            "-in",
            path_str(path)?,
            "-passin",
            &format!("pass:{password}"),
            "-cacerts",
            "-nokeys",
        ],
    )?;
    let leaf_details = extract_cert_chain_details(openssl_leaf.stdout.as_bytes())?;
    let chain_details = extract_cert_chain_details(openssl_chain.stdout.as_bytes())?;
    assert_eq!(leaf_details.len(), 1);
    assert_eq!(leaf_details[0].common_name, "svc.example.test");
    assert_eq!(chain_details.len(), 1);
    assert_eq!(chain_details[0].common_name, "SSL Toolbox Test Root CA");

    let keytool = run_command(
        "keytool",
        &[
            "-list",
            "-v",
            "-storetype",
            "PKCS12",
            "-keystore",
            path_str(path)?,
            "-storepass",
            password,
        ],
    )?;
    assert!(
        keytool.stdout.contains("Certificate chain length: 2"),
        "legacy PFX keytool output did not contain the expected chain length:\n{}",
        keytool.stdout
    );

    Ok(())
}

fn run_command(program: &str, args: &[&str]) -> Result<CommandOutput, Box<dyn Error>> {
    let output = Command::new(program).args(args).output()?;
    ensure_success(program, args, output)
}

fn ensure_success(
    program: &str,
    args: &[&str],
    output: Output,
) -> Result<CommandOutput, Box<dyn Error>> {
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    if !output.status.success() {
        return Err(format!(
            "command failed: {} {}\nstdout:\n{}\nstderr:\n{}",
            program,
            args.join(" "),
            stdout,
            stderr
        )
        .into());
    }
    Ok(CommandOutput { stdout, stderr })
}

fn command_exists(name: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };

    if cfg!(windows) {
        env::split_paths(&path)
            .any(|dir| dir.join(name).is_file() || dir.join(format!("{name}.exe")).is_file())
    } else {
        env::split_paths(&path).any(|dir| dir.join(name).is_file())
    }
}

fn normalize_pem(value: &str) -> String {
    value.lines().map(str::trim).collect::<Vec<_>>().join("\n")
}

/// Collapse ` = ` to `=` so assertions work with any OpenSSL version.
/// Older versions print `CN=foo`, newer ones print `CN = foo`.
fn normalize_openssl_subject(s: &str) -> String {
    s.replace(" = ", "=")
}

fn path_str(path: &Path) -> Result<&str, Box<dyn Error>> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()).into())
}

struct CommandOutput {
    stdout: String,
    stderr: String,
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(prefix: &str) -> Result<Self, Box<dyn Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = env::temp_dir().join(format!("{prefix}-{}-{unique}", std::process::id()));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

//! Behavior tests driven through the ops executor seam (ARCHITECTURE.md §2.7).
//!
//! These cover the decisions the executor makes that `ssl-toolbox-core` does
//! not: when a private key may be created implicitly, when a passphrase is
//! mandatory, and what happens to on-disk artifacts when a request is refused.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ssl_toolbox_ops::ops::{OpOutcome, OpRequest, run};
use ssl_toolbox_ops::secret::Secret;

const CONF: &str = r#"[req_distinguished_name]
C = US
ST = Texas
L = Austin
O = SSL Toolbox
OU = Platform
CN = svc.example.test

[ alt_names ]
DNS.1 = svc.example.test
"#;

#[test]
fn generating_a_csr_will_not_silently_create_a_missing_private_key() {
    // A user asking for a CSR against a key they believe exists has almost
    // certainly mistyped the path. Creating a fresh key instead would hand back
    // a CSR that no existing certificate or key escrow record matches.
    let dir = TestDir::new("csr-no-implicit-key");
    let conf = dir.write("openssl.cnf", CONF);
    let key = dir.path("absent.key");
    let csr = dir.path("server.csr");

    let error = run(OpRequest::GenerateCsr {
        conf: conf.clone(),
        key: key.clone(),
        csr: csr.clone(),
        key_password: Secret::new("changeit"),
        create_key_if_missing: false,
    })
    .expect_err("expected refusal when the private key does not exist");

    assert!(
        error.to_string().contains("does not exist"),
        "error should name the missing key, got: {error}"
    );
    assert!(
        !Path::new(&key).exists(),
        "no private key may be written when the request was refused"
    );
    assert!(
        !Path::new(&csr).exists(),
        "no CSR may be written when the request was refused"
    );
}

#[test]
fn creating_a_key_alongside_a_csr_requires_a_passphrase() {
    // The toolbox only emits encrypted private keys. An empty passphrase would
    // reach OpenSSL as a valid-but-empty secret, producing a key that is
    // encrypted in name only.
    let dir = TestDir::new("csr-requires-passphrase");
    let conf = dir.write("openssl.cnf", CONF);
    let key = dir.path("new.key");

    let error = run(OpRequest::GenerateCsr {
        conf,
        key: key.clone(),
        csr: dir.path("server.csr"),
        key_password: Secret::new(""),
        create_key_if_missing: true,
    })
    .expect_err("expected refusal when creating a key with no passphrase");

    assert!(
        error.to_string().contains("passphrase is required"),
        "error should explain the passphrase requirement, got: {error}"
    );
    assert!(
        !Path::new(&key).exists(),
        "no private key may be written when the request was refused"
    );
}

#[test]
fn generating_a_csr_may_create_the_key_when_explicitly_allowed() {
    let dir = TestDir::new("csr-with-key-creation");
    let conf = dir.write("openssl.cnf", CONF);
    let key = dir.path("new.key");
    let csr = dir.path("server.csr");

    let result = run(OpRequest::GenerateCsr {
        conf,
        key: key.clone(),
        csr: csr.clone(),
        key_password: Secret::new("changeit"),
        create_key_if_missing: true,
    })
    .expect("key creation was explicitly allowed");

    match result.outcome {
        OpOutcome::CsrGenerated { key_created, .. } => assert!(
            key_created,
            "outcome must report that the key was created, so a front-end can \
             tell the user a new key now exists"
        ),
        other => panic!("expected CsrGenerated, got {other:?}"),
    }

    let key_pem = fs::read_to_string(&key).expect("private key should exist");
    assert!(
        key_pem.contains("ENCRYPTED PRIVATE KEY"),
        "generated key must be encrypted, got header: {:?}",
        key_pem.lines().next()
    );
    assert!(
        fs::read_to_string(&csr)
            .expect("CSR should exist")
            .contains("BEGIN CERTIFICATE REQUEST"),
        "CSR file must contain a PEM CSR"
    );
}

#[test]
fn an_existing_key_is_reused_rather_than_overwritten() {
    // Overwriting an in-use private key is unrecoverable: every certificate
    // already issued against it becomes orphaned.
    let dir = TestDir::new("csr-reuses-key");
    let conf = dir.write("openssl.cnf", CONF);
    let key = dir.path("server.key");

    run(OpRequest::CreateKey {
        out: key.clone(),
        password: Secret::new("changeit"),
    })
    .expect("key creation should succeed");
    let original = fs::read_to_string(&key).expect("key should exist");

    let result = run(OpRequest::GenerateCsr {
        conf,
        key: key.clone(),
        csr: dir.path("server.csr"),
        key_password: Secret::new("changeit"),
        create_key_if_missing: true,
    })
    .expect("CSR generation against an existing key should succeed");

    match result.outcome {
        OpOutcome::CsrGenerated { key_created, .. } => {
            assert!(!key_created, "an existing key must not be reported as created")
        }
        other => panic!("expected CsrGenerated, got {other:?}"),
    }
    assert_eq!(
        original,
        fs::read_to_string(&key).expect("key should still exist"),
        "the existing private key must be left byte-identical"
    );
}

#[test]
fn an_unsupported_conversion_format_is_refused_without_writing_output() {
    let dir = TestDir::new("convert-bad-format");
    let input = dir.write("cert.pem", "not-really-a-cert");
    let output = dir.path("cert.out");

    let error = run(OpRequest::ConvertFormat {
        input,
        output: output.clone(),
        format: "jpeg".to_string(),
    })
    .expect_err("expected refusal for an unsupported format");

    let message = error.to_string();
    assert!(
        message.contains("jpeg"),
        "error should name the rejected format, got: {message}"
    );
    assert!(
        message.contains("pem") && message.contains("der") && message.contains("base64"),
        "error should list the supported formats, got: {message}"
    );
    assert!(
        !Path::new(&output).exists(),
        "no output file may be written for a refused conversion"
    );
}

/// The GUI is TypeScript; nothing type-checks the JSON that crosses the webview
/// IPC boundary. This pins the wire shape so a field rename on either side
/// fails here rather than silently at runtime in the app.
#[test]
fn op_requests_deserialize_from_the_camel_case_wire_shape() {
    let request: OpRequest = serde_json::from_str(
        r#"{
            "op": "verifyEndpoint",
            "protocol": "https",
            "host": "example.test",
            "port": 8443,
            "fullScan": true,
            "exportCertsDir": "/tmp/certs"
        }"#,
    )
    .expect("the GUI's request shape must deserialize");

    match request {
        OpRequest::VerifyEndpoint {
            protocol,
            host,
            port,
            verify,
            full_scan,
            export_certs_dir,
            ..
        } => {
            assert_eq!(protocol, ssl_toolbox_ops::EndpointProtocol::Https);
            assert_eq!(host, "example.test");
            assert_eq!(port, Some(8443));
            assert!(full_scan);
            assert_eq!(export_certs_dir.as_deref(), Some("/tmp/certs"));
            assert!(
                verify,
                "certificate validation must default to on when the field is omitted"
            );
        }
        other => panic!("expected VerifyEndpoint, got {other:?}"),
    }
}

/// A bad collect format is rejected before the CA plugin is constructed.
///
/// Otherwise the user's first error is "SCM_CLIENT_ID not set" — a credentials
/// problem they do not have — instead of the typo they actually made. Ordering
/// this check first also avoids a pointless authenticated round trip.
#[test]
fn an_unsupported_collect_format_is_refused_before_contacting_the_ca() {
    let error = run(OpRequest::CaCollectCert {
        request_id: "12345".to_string(),
        out: "/nonexistent/should-not-be-written.pem".to_string(),
        format: "jpeg".to_string(),
        debug: false,
    })
    .expect_err("expected refusal for an unsupported collect format");

    let message = error.to_string();
    assert!(
        message.contains("jpeg") && message.contains("pkcs7"),
        "error should name the bad format and list valid ones, got: {message}"
    );
    assert!(
        !message.contains("SCM_") && !message.contains("No CA plugin"),
        "format validation must happen before CA configuration, got: {message}"
    );
}

/// The verification outcome must arrive at the frontend as one flat object.
///
/// `OpOutcome::EndpointVerified` is an internally tagged *newtype* variant, so
/// whether serde flattens the inner struct alongside the `outcome` tag or nests
/// it decides the entire shape `ui/src/lib/types.ts` destructures. Getting this
/// wrong breaks the whole Verify view at runtime with no compile-time signal on
/// either side of the IPC boundary.
#[test]
fn endpoint_verification_serializes_flat_alongside_its_outcome_tag() {
    let outcome = OpOutcome::EndpointVerified(Box::new(sample_verification()));
    let json = serde_json::to_value(&outcome).expect("outcome should serialize");

    let object = json.as_object().expect("outcome should be a JSON object");

    assert_eq!(
        object.get("outcome").and_then(|value| value.as_str()),
        Some("endpointVerified"),
        "the discriminant the frontend switches on must be `outcome`"
    );

    // Flat, not nested under a payload key.
    for key in [
        "protocol",
        "host",
        "port",
        "result",
        "audit",
        "ldapConfig",
        "ldapConfigError",
        "exportedCerts",
    ] {
        assert!(
            object.contains_key(key),
            "`{key}` must sit alongside the outcome tag, not nested. Got keys: {:?}",
            object.keys().collect::<Vec<_>>()
        );
    }

    assert_eq!(
        object.get("protocol").and_then(|value| value.as_str()),
        Some("https"),
        "protocol must serialize lowercase to match the EndpointProtocol union"
    );

    // The nested TLS result keeps ssl-toolbox-core's snake_case field names.
    let result = object
        .get("result")
        .and_then(|value| value.as_object())
        .expect("result should be an object");
    for key in ["cert_chain", "version_support", "chain_sent_out_of_order"] {
        assert!(
            result.contains_key(key),
            "TlsCheckResult field `{key}` must stay snake_case. Got keys: {:?}",
            result.keys().collect::<Vec<_>>()
        );
    }
}

/// Outcomes that carry a path must name it `path`, since every success banner
/// in the UI reads that one field.
#[test]
fn simple_outcomes_serialize_with_the_keys_the_ui_reads() {
    let key_created = serde_json::to_value(OpOutcome::KeyCreated {
        path: "server.key".into(),
    })
    .expect("should serialize");

    assert_eq!(key_created["outcome"], "keyCreated");
    assert_eq!(key_created["path"], "server.key");

    let csr = serde_json::to_value(OpOutcome::CsrGenerated {
        csr_path: "server.csr".into(),
        key_path: "server.key".into(),
        key_created: true,
    })
    .expect("should serialize");

    assert_eq!(csr["outcome"], "csrGenerated");
    assert_eq!(csr["csrPath"], "server.csr");
    assert_eq!(csr["keyPath"], "server.key");
    assert_eq!(csr["keyCreated"], true);
}

fn sample_verification() -> ssl_toolbox_ops::ops::EndpointVerification {
    use ssl_toolbox_ops::EndpointProtocol;
    use ssl_toolbox_ops::audit::{
        ValidationAuditEntry, ValidationAuditStatus, ValidationComparison,
    };
    use ssl_toolbox_ops::workflow::ActionKind;

    ssl_toolbox_ops::ops::EndpointVerification {
        protocol: EndpointProtocol::Https,
        host: "example.com".into(),
        port: 443,
        result: ssl_toolbox_core::TlsCheckResult {
            host: "example.com".into(),
            port: 443,
            cipher: ssl_toolbox_core::CipherInfo {
                name: "TLS_AES_256_GCM_SHA384".into(),
                bits: 256,
                protocol: "TLSv1.3".into(),
            },
            cert_chain: Vec::new(),
            cert_chain_pem: Vec::new(),
            version_support: Vec::new(),
            cipher_scan: Vec::new(),
            validation: None,
            chain_sent_out_of_order: false,
        },
        audit: ValidationAuditEntry {
            timestamp_secs: 1_704_067_200,
            timestamp_utc: "2024-01-01T00:00:00Z".into(),
            kind: ActionKind::VerifyHttps,
            host: "example.com".into(),
            port: 443,
            certificate_validation_requested: true,
            full_scan: false,
            status: ValidationAuditStatus::Success,
            result: None,
            error: None,
            comparison: ValidationComparison {
                previous_timestamp_utc: None,
                changes: Vec::new(),
            },
        },
        ldap_config: None,
        ldap_config_error: None,
        exported_certs: Vec::new(),
    }
}

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ssl-toolbox-ops-{label}-{nanos}"));
        fs::create_dir_all(&dir).expect("temp dir should be creatable");
        Self(dir)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).display().to_string()
    }

    fn write(&self, name: &str, contents: &str) -> String {
        let path = self.path(name);
        fs::write(&path, contents).expect("fixture should be writable");
        path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

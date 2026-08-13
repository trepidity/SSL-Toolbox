//! Behavior tests for viewing and editing an existing OpenSSL config, driven
//! through the ops executor seam (`ARCHITECTURE.md` §2.7).
//!
//! The governing product decision is that the **file text is the source of
//! truth**. The toolbox reads a config well enough to describe it, but it never
//! regenerates one from that reading: a config carries comments, extra sections
//! and hand-tuned extensions that `ConfigInputs` does not model, and silently
//! dropping them would be worse than not offering the feature.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ssl_toolbox_core::{ConfigInputs, SanKind, SanName};
use ssl_toolbox_ops::ops::{OpOutcome, OpRequest, run};

/// A config with the shapes real ones have: comments, an unmodelled section,
/// `[ alt_names ]` spelled with inner spaces, and CRLF nowhere in sight.
const HAND_TUNED: &str = r#"# Written by hand. Do not regenerate.
[req]
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no
default_bits       = 4096

[req_distinguished_name]
C  = US
ST = Texas
L  = Dallas
O  = Example Organization
OU = Platform Engineering
CN = gateway.example.test

[ alt_names ]
DNS.1 = gateway.example.test
DNS.2 = api.gateway.example.test
IP.1  = 10.20.30.40

[v3_req]
extendedKeyUsage = serverAuth
subjectAltName   = @alt_names

[custom_oid_section]
1.3.6.1.4.1.311.20.2 = ASN1:UTF8String:SubCA
"#;

#[test]
fn loading_a_config_returns_the_file_text_byte_for_byte() {
    // The editor edits what is on disk. If the load path normalises whitespace,
    // reorders keys or strips comments, then the first save silently rewrites a
    // file the user only meant to look at.
    let dir = TestDir::new("load-verbatim");
    let path = dir.write("request.cnf", HAND_TUNED);

    let result = run(OpRequest::LoadConfig { path: path.clone() }).expect("config should load");

    match result.outcome {
        OpOutcome::ConfigLoaded { text, .. } => {
            assert_eq!(text, HAND_TUNED, "loaded text must match the file exactly");
        }
        other => panic!("expected ConfigLoaded, got {other:?}"),
    }
}

#[test]
fn loading_a_config_reports_the_fields_the_toolbox_understands() {
    // The point of the insight panel: tell the operator what this file actually
    // says, so they are not reading INI by eye to check the CN and the SANs.
    let dir = TestDir::new("load-summary");
    let path = dir.write("request.cnf", HAND_TUNED);

    let result = run(OpRequest::LoadConfig { path }).expect("config should load");

    match result.outcome {
        OpOutcome::ConfigLoaded { summary, .. } => {
            assert_eq!(summary.common_name.as_deref(), Some("gateway.example.test"));
            assert_eq!(
                summary.organization.as_deref(),
                Some("Example Organization")
            );
            assert_eq!(summary.org_unit.as_deref(), Some("Platform Engineering"));
            assert_eq!(summary.country.as_deref(), Some("US"));
            assert_eq!(summary.key_size, Some(4096));
            assert_eq!(summary.extended_key_usage.as_deref(), Some("serverAuth"));
            assert_eq!(
                summary.sans,
                vec![
                    SanName::new(SanKind::Dns, "gateway.example.test"),
                    SanName::new(SanKind::Dns, "api.gateway.example.test"),
                    SanName::new(SanKind::Ip, "10.20.30.40"),
                ]
            );
        }
        other => panic!("expected ConfigLoaded, got {other:?}"),
    }
}

#[test]
fn a_section_the_toolbox_does_not_model_is_reported_rather_than_ignored() {
    // Preserving unknown content is only half the promise. The operator has to
    // be told that content exists, or "the panel shows everything" becomes a
    // false belief the moment a config carries a custom OID.
    let dir = TestDir::new("load-unmodelled");
    let path = dir.write("request.cnf", HAND_TUNED);

    let result = run(OpRequest::LoadConfig { path }).expect("config should load");

    match result.outcome {
        OpOutcome::ConfigLoaded { summary, .. } => {
            assert!(
                summary.sections.iter().any(|s| s == "custom_oid_section"),
                "every section must be listed, got {:?}",
                summary.sections
            );
            assert!(
                summary
                    .warnings
                    .iter()
                    .any(|w| w.contains("custom_oid_section")),
                "an unmodelled section must be surfaced as a warning, got {:?}",
                summary.warnings
            );
        }
        other => panic!("expected ConfigLoaded, got {other:?}"),
    }
}

#[test]
fn a_common_name_absent_from_the_san_list_is_warned_about() {
    // Every current TLS client ignores CN and matches on SANs alone, so a config
    // whose CN is not also a SAN produces a certificate that fails hostname
    // verification for the very name the operator typed.
    let dir = TestDir::new("load-cn-not-in-sans");
    let path = dir.write(
        "request.cnf",
        "[req_distinguished_name]\nCN = missing.example.test\n\n[alt_names]\nDNS.1 = other.example.test\n",
    );

    let result = run(OpRequest::LoadConfig { path }).expect("config should load");

    match result.outcome {
        OpOutcome::ConfigLoaded { summary, .. } => {
            assert!(
                summary
                    .warnings
                    .iter()
                    .any(|w| w.contains("missing.example.test")),
                "CN missing from SANs must be warned about, got {:?}",
                summary.warnings
            );
        }
        other => panic!("expected ConfigLoaded, got {other:?}"),
    }
}

#[test]
fn dn_and_san_sections_are_found_by_following_the_names_the_config_uses() {
    // `[req] distinguished_name` and `subjectAltName = @…` may point at any
    // section name. Reading only the conventional spellings would report "no
    // common name" for a file that plainly declares one.
    let dir = TestDir::new("load-renamed-sections");
    let path = dir.write(
        "request.cnf",
        "[req]\ndistinguished_name = dn\nreq_extensions = exts\n\n\
         [dn]\nCN = renamed.example.test\n\n\
         [exts]\nsubjectAltName = @names\n\n\
         [names]\nDNS.1 = renamed.example.test\n",
    );

    let result = run(OpRequest::LoadConfig { path }).expect("config should load");

    match result.outcome {
        OpOutcome::ConfigLoaded { summary, .. } => {
            assert_eq!(summary.common_name.as_deref(), Some("renamed.example.test"));
            assert_eq!(
                summary.sans,
                vec![SanName::new(SanKind::Dns, "renamed.example.test")]
            );
        }
        other => panic!("expected ConfigLoaded, got {other:?}"),
    }
}

/// The long-name spelling of every DN attribute, as `openssl req` writes it and
/// as real hand-maintained configs use it.
const LONG_NAMES: &str = r#"[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no

[ req_distinguished_name ]
countryName            = US
stateOrProvinceName    = Texas
localityName           = Dallas
organizationName       = Example Organization
organizationalUnitName = Platform Engineering
commonName             = qa.gateway.example.test
emailAddress           = certificates@example.test

[ v3_req ]
basicConstraints     = CA:FALSE
keyUsage             = critical, digitalSignature, keyEncipherment
extendedKeyUsage     = serverAuth
subjectKeyIdentifier = hash
subjectAltName       = @alt_names

[ alt_names ]
DNS.1 = qa.gateway.example.test
"#;

#[test]
fn dn_attributes_are_read_whether_spelled_short_or_long() {
    // OpenSSL accepts `CN` and `commonName` interchangeably. Reading only the
    // short form reports an empty subject for a config that fully specifies one,
    // and then compounds it by warning "No CN found" about a config whose CN is
    // present and correctly mirrored into the SAN list.
    let dir = TestDir::new("load-long-names");
    let path = dir.write("request.cnf", LONG_NAMES);

    let result = run(OpRequest::LoadConfig { path }).expect("config should load");

    match result.outcome {
        OpOutcome::ConfigLoaded { summary, .. } => {
            assert_eq!(
                summary.common_name.as_deref(),
                Some("qa.gateway.example.test")
            );
            assert_eq!(summary.country.as_deref(), Some("US"));
            assert_eq!(summary.state.as_deref(), Some("Texas"));
            assert_eq!(summary.locality.as_deref(), Some("Dallas"));
            assert_eq!(
                summary.organization.as_deref(),
                Some("Example Organization")
            );
            assert_eq!(summary.org_unit.as_deref(), Some("Platform Engineering"));
            assert_eq!(summary.email.as_deref(), Some("certificates@example.test"));
            assert!(
                summary.warnings.is_empty(),
                "a fully specified config whose CN is in its SAN list warrants no \
                 warnings, got {:?}",
                summary.warnings
            );
        }
        other => panic!("expected ConfigLoaded, got {other:?}"),
    }
}

#[test]
fn dn_attributes_carrying_an_openssl_ordering_prefix_are_read() {
    // `0.organizationName` / `1.organizationName` is how OpenSSL lets a subject
    // carry two values for one attribute. The prefix is syntax, not part of the
    // attribute name, and both values belong to the subject.
    let dir = TestDir::new("load-ordering-prefix");
    let path = dir.write(
        "request.cnf",
        "[req_distinguished_name]\n\
         0.organizationName = Example Organization\n\
         1.organizationName = Example Org\n\
         0.commonName       = prefixed.example.test\n",
    );

    let result = run(OpRequest::LoadConfig { path }).expect("config should load");

    match result.outcome {
        OpOutcome::ConfigLoaded { summary, .. } => {
            assert_eq!(
                summary.common_name.as_deref(),
                Some("prefixed.example.test")
            );
            assert_eq!(
                summary.organization.as_deref(),
                Some("Example Organization, Example Org"),
                "both ordered values belong to the subject"
            );
        }
        other => panic!("expected ConfigLoaded, got {other:?}"),
    }
}

#[test]
fn every_san_type_openssl_can_express_is_read_with_its_rfc_type() {
    // RFC 5280 §4.2.1.6 defines nine GeneralName choices; OpenSSL config syntax
    // reaches seven of them. Reading only DNS and IP silently loses the rest, so an
    // operator would see "1 SAN" for a config requesting six.
    let dir = TestDir::new("load-all-san-types");
    let path = dir.write(
        "request.cnf",
        "[req_distinguished_name]\nCN = all.example.test\n\n\
         [alt_names]\n\
         DNS.1 = all.example.test\n\
         IP.1 = 10.0.0.5\n\
         email.1 = admin@example.test\n\
         URI.1 = https://example.test/\n\
         RID.1 = 1.3.6.1.5.5.7.3.1\n\
         otherName.1 = 1.3.6.1.4.1.311.20.2.3;UTF8:user@example.test\n\
         dirName.1 = dir_sect\n\n\
         [dir_sect]\nCN = Example Directory\nO = Example Org\n",
    );

    let result = run(OpRequest::LoadConfig { path }).expect("config should load");

    match result.outcome {
        OpOutcome::ConfigLoaded { summary, .. } => {
            assert_eq!(
                summary.sans,
                vec![
                    SanName::new(SanKind::Dns, "all.example.test"),
                    SanName::new(SanKind::Ip, "10.0.0.5"),
                    SanName::new(SanKind::Email, "admin@example.test"),
                    SanName::new(SanKind::Uri, "https://example.test/"),
                    SanName::new(SanKind::RegisteredId, "1.3.6.1.5.5.7.3.1"),
                    SanName::new(
                        SanKind::OtherName,
                        "1.3.6.1.4.1.311.20.2.3;UTF8:user@example.test"
                    ),
                    // The section reference is resolved to the DN it holds, so the
                    // reader shows the actual name rather than a bare pointer.
                    SanName::new(SanKind::DirName, "CN=Example Directory, O=Example Org"),
                ]
            );
        }
        other => panic!("expected ConfigLoaded, got {other:?}"),
    }
}

#[test]
fn a_key_in_alt_names_that_is_not_a_san_type_is_warned_about() {
    // `DSN.1` is a plausible typo for `DNS.1`. OpenSSL ignores it, so the name is
    // simply missing from the certificate with nothing said.
    let dir = TestDir::new("load-typo-san");
    let path = dir.write(
        "request.cnf",
        "[req_distinguished_name]\nCN = typo.example.test\n\n\
         [alt_names]\nDNS.1 = typo.example.test\nDSN.2 = oops.example.test\n",
    );

    let result = run(OpRequest::LoadConfig { path }).expect("config should load");

    match result.outcome {
        OpOutcome::ConfigLoaded { summary, .. } => {
            assert!(
                summary.warnings.iter().any(|w| w.contains("DSN.2")),
                "an unrecognised SAN key must be flagged, got {:?}",
                summary.warnings
            );
        }
        other => panic!("expected ConfigLoaded, got {other:?}"),
    }
}

#[test]
fn writing_a_config_emits_each_san_under_its_openssl_key_numbered_per_type() {
    // OpenSSL numbers `[alt_names]` per type. A single shared counter would emit
    // `IP.2` as the first IP address, and OpenSSL would then ignore it.
    let dir = TestDir::new("write-all-san-types");
    let out = dir.path("written.cnf");

    run(OpRequest::GenerateConfig {
        inputs: Box::new(ConfigInputs {
            common_name: "svc.example.test".to_string(),
            country: "US".to_string(),
            state: "Texas".to_string(),
            locality: "Dallas".to_string(),
            organization: "Example Org".to_string(),
            org_unit: "Platform".to_string(),
            email: "admin@example.test".to_string(),
            sans: vec![
                SanName::new(SanKind::Dns, "alt.example.test"),
                SanName::new(SanKind::Ip, "10.0.0.5"),
                SanName::new(SanKind::Ip, "10.0.0.6"),
                SanName::new(SanKind::Email, "admin@example.test"),
                SanName::new(SanKind::Uri, "https://example.test/"),
                SanName::new(SanKind::RegisteredId, "1.3.6.1.5.5.7.3.1"),
                SanName::new(
                    SanKind::OtherName,
                    "1.3.6.1.4.1.311.20.2.3;UTF8:user@example.test",
                ),
            ],
            key_size: 2048,
            extended_key_usage: "serverAuth".to_string(),
        }),
        out: out.clone(),
    })
    .expect("config should be written");

    let written = fs::read_to_string(&out).expect("config should be readable");

    for expected in [
        "DNS.1 = svc.example.test", // the CN always leads
        "DNS.2 = alt.example.test",
        "IP.1 = 10.0.0.5",
        "IP.2 = 10.0.0.6",
        "email.1 = admin@example.test",
        "URI.1 = https://example.test/",
        "RID.1 = 1.3.6.1.5.5.7.3.1",
        "otherName.1 = 1.3.6.1.4.1.311.20.2.3;UTF8:user@example.test",
    ] {
        assert!(
            written.contains(expected),
            "expected {expected:?} in written config:\n{written}"
        );
    }
}

#[test]
fn writing_a_directory_name_san_emits_the_section_it_references() {
    // `dirName` is the one type whose value is a section reference rather than an
    // inline string. Emitting the reference without the section produces a config
    // OpenSSL refuses to load.
    let dir = TestDir::new("write-dirname-san");
    let out = dir.path("dirname.cnf");

    run(OpRequest::GenerateConfig {
        inputs: Box::new(base_inputs(vec![SanName::new(
            SanKind::DirName,
            "CN=Example Directory,O=Example Org",
        )])),
        out: out.clone(),
    })
    .expect("config should be written");

    let written = fs::read_to_string(&out).expect("config should be readable");
    assert!(
        written.contains("dirName.1 = dirname_1"),
        "expected a dirName reference:\n{written}"
    );
    assert!(
        written.contains("[ dirname_1 ]")
            && written.contains("CN = Example Directory")
            && written.contains("O = Example Org"),
        "expected the referenced section to be defined:\n{written}"
    );
}

#[test]
fn an_ip_san_that_is_not_an_address_is_refused_before_anything_is_written() {
    // Left to OpenSSL this surfaces at CSR time as an error that names no field.
    let dir = TestDir::new("write-bad-ip");
    let out = dir.path("bad.cnf");

    let error = run(OpRequest::GenerateConfig {
        inputs: Box::new(base_inputs(vec![SanName::new(SanKind::Ip, "10.0.0.999")])),
        out: out.clone(),
    })
    .expect_err("an invalid IP SAN must be refused");

    let message = format!("{error:#}");
    assert!(
        message.contains("10.0.0.999"),
        "the error must name the offending value, got {message}"
    );
    assert!(
        !PathBuf::from(&out).exists(),
        "no config should be written when a SAN is rejected"
    );
}

#[test]
fn malformed_oid_sans_are_refused_before_anything_is_written() {
    // Invalid registered IDs and otherNames would otherwise produce a config
    // that fails only later in OpenSSL, disconnected from the SAN entry the
    // operator supplied.
    for (kind, value) in [
        (SanKind::RegisteredId, "1..3"),
        (SanKind::OtherName, "not-an-oid;UTF8:value"),
        (SanKind::OtherName, "1.3.6.1;UTF8"),
    ] {
        let dir = TestDir::new("write-bad-oid-san");
        let out = dir.path("bad.cnf");

        let error = run(OpRequest::GenerateConfig {
            inputs: Box::new(base_inputs(vec![SanName::new(kind, value)])),
            out: out.clone(),
        })
        .expect_err("a malformed OID SAN must be refused");

        assert!(
            error.to_string().contains(value),
            "the error must name the offending value, got {error}"
        );
        assert!(
            !PathBuf::from(&out).exists(),
            "no config should be written when {value:?} is rejected"
        );
    }
}

fn base_inputs(sans: Vec<SanName>) -> ConfigInputs {
    ConfigInputs {
        common_name: "svc.example.test".to_string(),
        country: "US".to_string(),
        state: "Texas".to_string(),
        locality: "Dallas".to_string(),
        organization: "Example Org".to_string(),
        org_unit: "Platform".to_string(),
        email: "admin@example.test".to_string(),
        sans,
        key_size: 2048,
        extended_key_usage: "serverAuth".to_string(),
    }
}

#[test]
fn trailing_comments_and_quotes_are_not_read_as_part_of_a_value() {
    // A CN of `host # primary` would be carried into a CSR verbatim and rejected
    // by the CA, with nothing in the UI explaining why.
    let dir = TestDir::new("load-comments");
    let path = dir.write(
        "request.cnf",
        "[req_distinguished_name]\nCN = host.example.test # the primary name\nO = \"Quoted Org\"\n",
    );

    let result = run(OpRequest::LoadConfig { path }).expect("config should load");

    match result.outcome {
        OpOutcome::ConfigLoaded { summary, .. } => {
            assert_eq!(summary.common_name.as_deref(), Some("host.example.test"));
            assert_eq!(summary.organization.as_deref(), Some("Quoted Org"));
        }
        other => panic!("expected ConfigLoaded, got {other:?}"),
    }
}

#[test]
fn saving_writes_the_edited_text_verbatim() {
    // Saving must not route back through the config generator: that would
    // reformat the file and drop everything `ConfigInputs` cannot express.
    let dir = TestDir::new("save-verbatim");
    let path = dir.write("request.cnf", "[req]\nprompt = no\n");
    let edited = format!("{HAND_TUNED}\n# edited\n");

    run(OpRequest::SaveConfig {
        path: path.clone(),
        text: edited.clone(),
    })
    .expect("config should save");

    let on_disk = fs::read_to_string(&path).expect("saved config should be readable");
    assert_eq!(on_disk, edited, "saved bytes must match the submitted text");
}

#[test]
fn saving_over_an_existing_config_backs_up_the_previous_contents_first() {
    // The backup only has value if it holds the text being replaced. Writing the
    // file and *then* copying it produces a .bak identical to the new contents —
    // a backup that cannot restore anything.
    let dir = TestDir::new("save-backup");
    let original = "[req]\nprompt = no\n# the version worth recovering\n";
    let path = dir.write("request.cnf", original);

    let result = run(OpRequest::SaveConfig {
        path: path.clone(),
        text: "[req]\nprompt = yes\n".to_string(),
    })
    .expect("config should save");

    let backup = match result.outcome {
        OpOutcome::ConfigSaved { backup, .. } => {
            backup.expect("overwriting an existing config must report a backup path")
        }
        other => panic!("expected ConfigSaved, got {other:?}"),
    };

    let backed_up = fs::read_to_string(&backup).expect("backup should exist on disk");
    assert_eq!(
        backed_up, original,
        "the backup must hold the contents that were replaced"
    );
}

#[test]
fn saving_a_config_that_does_not_exist_yet_creates_no_backup() {
    // There is nothing to preserve, and an empty `.cnf.bak` sitting next to a
    // fresh config is just litter in the operator's certificate directory.
    let dir = TestDir::new("save-new-no-backup");
    let path = dir.path("brand-new.cnf");

    let result = run(OpRequest::SaveConfig {
        path: path.clone(),
        text: "[req]\nprompt = no\n".to_string(),
    })
    .expect("config should save");

    match result.outcome {
        OpOutcome::ConfigSaved { backup, .. } => {
            assert!(backup.is_none(), "expected no backup, got {backup:?}");
        }
        other => panic!("expected ConfigSaved, got {other:?}"),
    }
    assert!(
        !PathBuf::from(format!("{path}.bak")).exists(),
        "no .bak file should be created for a new config"
    );
}

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ssl-toolbox-cnf-{label}-{nanos}"));
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

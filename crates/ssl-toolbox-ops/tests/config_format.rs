//! Grammar coverage for the OpenSSL configuration file format, driven through the
//! ops executor seam (`ARCHITECTURE.md` §2.7).
//!
//! The format is defined by OpenSSL's own `config(5)` — it is not an RFC. These
//! tests pin the constructs that a config in the wild actually uses and that a
//! naive line-splitting reader gets wrong: a default section above the first
//! `[section]`, `$variable` expansion, quoting, escapes, line continuation, and
//! the `.include` / `.pragma` directives.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ssl_toolbox_ops::ops::{OpOutcome, OpRequest, run};

fn summary_of(path: String) -> ssl_toolbox_core::ConfigSummary {
    match run(OpRequest::LoadConfig { path })
        .expect("config should load")
        .outcome
    {
        OpOutcome::ConfigLoaded { summary, .. } => summary,
        other => panic!("expected ConfigLoaded, got {other:?}"),
    }
}

#[test]
fn a_variable_defined_above_the_first_section_is_available_for_expansion() {
    // `config(5)`: entries before any `[section]` belong to the default section.
    // Dropping them loses both the values and every `$variable` that depends on
    // them — and defining a domain once at the top is a common config idiom.
    let dir = TestDir::new("default-section");
    let path = dir.write(
        "request.cnf",
        "domain = example.test\n\n\
         [ req ]\ndistinguished_name = dn\n\n\
         [ dn ]\nCN = www.$domain\n",
    );

    let summary = summary_of(path);
    assert_eq!(summary.common_name.as_deref(), Some("www.example.test"));
}

#[test]
fn variables_expand_in_every_form_the_format_defines() {
    // `$name`, `${name}`, and the `section::name` form that reaches across
    // sections. A reader that shows the literal `$dir/certs` is telling the
    // operator something the config does not say.
    let dir = TestDir::new("expansion-forms");
    let path = dir.write(
        "request.cnf",
        "host = svc\n\
         [ places ]\ntld = example.test\n\n\
         [ req ]\ndistinguished_name = dn\nreq_extensions = exts\n\n\
         [ dn ]\nCN = ${host}.$places::tld\nO = ${places::tld}\n\n\
         [ exts ]\nsubjectAltName = @alt\n\n\
         [ alt ]\nDNS.1 = $host.${places::tld}\n",
    );

    let summary = summary_of(path);
    assert_eq!(summary.common_name.as_deref(), Some("svc.example.test"));
    assert_eq!(summary.organization.as_deref(), Some("example.test"));
    assert_eq!(
        summary.sans.first().map(|san| san.value.as_str()),
        Some("svc.example.test")
    );
}

#[test]
fn an_environment_variable_reference_expands() {
    // `$ENV::NAME` is how a config parameterises itself per run — the CN of a
    // per-host certificate is a standard use.
    let dir = TestDir::new("env-expansion");
    // A unique name: tests in a binary share one process environment.
    unsafe { std::env::set_var("SSL_TOOLBOX_TEST_CN", "from-env.example.test") };
    let path = dir.write(
        "request.cnf",
        "[ req ]\ndistinguished_name = dn\n\n[ dn ]\nCN = $ENV::SSL_TOOLBOX_TEST_CN\n",
    );

    let summary = summary_of(path);
    assert_eq!(
        summary.common_name.as_deref(),
        Some("from-env.example.test")
    );
}

#[test]
fn a_hash_inside_a_quoted_value_is_not_a_comment() {
    // Truncating at the first `#` regardless of quoting silently shortens a
    // subject field, and the CA rejects the CSR with no hint which field it was.
    let dir = TestDir::new("quoted-hash");
    let path = dir.write(
        "request.cnf",
        "[ req ]\ndistinguished_name = dn\n\n[ dn ]\nO = \"Example # One\"\nCN = host.example.test\n",
    );

    let summary = summary_of(path);
    assert_eq!(summary.organization.as_deref(), Some("Example # One"));
}

#[test]
fn single_quotes_keep_their_contents_literal() {
    // `config(5)`: single quotes suppress escape and `$` processing, which is the
    // only way to put a literal `$` in a value.
    let dir = TestDir::new("single-quotes");
    let path = dir.write(
        "request.cnf",
        "[ req ]\ndistinguished_name = dn\n\n[ dn ]\nO = 'Cost $100 # each'\nCN = host.example.test\n",
    );

    let summary = summary_of(path);
    assert_eq!(summary.organization.as_deref(), Some("Cost $100 # each"));
}

#[test]
fn a_backslash_escapes_the_character_that_follows_it() {
    // Without escape handling `\$` expands as a variable and the value silently
    // becomes something the file never said.
    let dir = TestDir::new("escapes");
    let path = dir.write(
        "request.cnf",
        "[ req ]\ndistinguished_name = dn\n\n[ dn ]\nO = Cost \\$100\nCN = host.example.test\n",
    );

    let summary = summary_of(path);
    assert_eq!(summary.organization.as_deref(), Some("Cost $100"));
}

#[test]
fn a_trailing_backslash_continues_the_value_on_the_next_line() {
    // Long SAN lists and long DNs are wrapped this way. Treating each physical
    // line separately turns one value into a value plus a dropped fragment.
    let dir = TestDir::new("continuation");
    let path = dir.write(
        "request.cnf",
        "[ req ]\ndistinguished_name = dn\n\n\
         [ dn ]\nO = Baylor Scott \\\n& White Health\nCN = host.example.test\n",
    );

    let summary = summary_of(path);
    assert_eq!(
        summary.organization.as_deref(),
        Some("Baylor Scott & White Health")
    );
}

#[test]
fn an_included_file_contributes_its_sections() {
    // `.include` is how shared DN defaults are factored out across many configs.
    // Ignoring it reports an empty subject for a config that is complete on disk.
    let dir = TestDir::new("include");
    dir.write(
        "shared-dn.cnf",
        "[ dn ]\nCN = included.example.test\nO = Example Org\n",
    );
    let path = dir.write(
        "request.cnf",
        ".include shared-dn.cnf\n\n[ req ]\ndistinguished_name = dn\n",
    );

    let summary = summary_of(path);
    assert_eq!(summary.common_name.as_deref(), Some("included.example.test"));
    assert_eq!(summary.organization.as_deref(), Some("Example Org"));
}

#[test]
fn an_include_that_cannot_be_read_is_reported_rather_than_ignored() {
    // Silence here means the operator sees a subject with fields missing and no
    // reason why.
    let dir = TestDir::new("include-missing");
    let path = dir.write(
        "request.cnf",
        ".include no-such-file.cnf\n\n[ req ]\ndistinguished_name = dn\n\n[ dn ]\nCN = host.example.test\n",
    );

    let summary = summary_of(path);
    assert!(
        summary
            .warnings
            .iter()
            .any(|w| w.contains("no-such-file.cnf")),
        "an unreadable include must be surfaced, got {:?}",
        summary.warnings
    );
}

#[test]
fn a_directive_is_not_mistaken_for_a_section_or_an_entry() {
    // `.pragma` is valid syntax. Parsed as data it would show up as a bogus
    // section in the panel, and any pragma that changes parsing would be applied
    // silently — so it is consumed and reported instead.
    let dir = TestDir::new("pragma");
    let path = dir.write(
        "request.cnf",
        ".pragma dollarid:on\n\n[ req ]\ndistinguished_name = dn\n\n[ dn ]\nCN = host.example.test\n",
    );

    let summary = summary_of(path);
    assert_eq!(summary.common_name.as_deref(), Some("host.example.test"));
    assert!(
        summary.sections.iter().all(|s| s != ".pragma dollarid:on"),
        "a directive must not appear as a section, got {:?}",
        summary.sections
    );
    assert!(
        summary.warnings.iter().any(|w| w.contains("pragma")),
        "an unhonoured pragma must be surfaced, got {:?}",
        summary.warnings
    );
}

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ssl-toolbox-fmt-{label}-{nanos}"));
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

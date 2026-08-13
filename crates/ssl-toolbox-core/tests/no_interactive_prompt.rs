//! Loading key material must never fall back to OpenSSL's interactive prompt.
//!
//! OpenSSL's default passphrase callback prompts on the terminal and reads
//! stdin. Reaching it is a bug in every context the toolbox runs in: it
//! destroys piped stdin for CLI users, and a GUI has no terminal to answer it
//! at all. The observable, testable symptom is stdin consumption, so that is
//! what this asserts.
//!
//! The check runs in a child process because stdin belongs to the whole
//! process, not to a single test.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

const PROBE_ENV: &str = "SSL_TOOLBOX_STDIN_PROBE_KEY";
const SENTINEL: &str = "SENTINEL_LINE\nSECOND_LINE\n";

const CONF: &str = r#"[req_distinguished_name]
CN = svc.example.test

[ alt_names ]
DNS.1 = svc.example.test
"#;

#[test]
fn generating_a_csr_without_a_passphrase_does_not_consume_stdin() {
    // Child role: perform the real operation, then report what stdin still holds.
    if let Ok(key_path) = std::env::var(PROBE_ENV) {
        let dir = std::path::Path::new(&key_path)
            .parent()
            .expect("key path should have a parent");
        let conf = dir.join("openssl.cnf");
        std::fs::write(&conf, CONF).expect("conf should be writable");

        // No passphrase supplied for an encrypted key: this is the path that
        // used to reach OpenSSL's default prompt.
        let _ = ssl_toolbox_core::key_csr::generate_csr(
            conf.to_str().expect("utf-8 path"),
            &key_path,
            dir.join("out.csr").to_str().expect("utf-8 path"),
            None,
        );

        let mut remaining = String::new();
        std::io::stdin()
            .read_to_string(&mut remaining)
            .expect("stdin should be readable");
        print!("REMAINING:{remaining}");
        std::io::stdout().flush().expect("stdout should flush");
        return;
    }

    let Some(key_path) = encrypted_key_fixture() else {
        eprintln!("Skipping: `openssl` is unavailable to build an encrypted key fixture.");
        return;
    };

    let mut child = Command::new(std::env::current_exe().expect("test binary path"))
        .arg("generating_a_csr_without_a_passphrase_does_not_consume_stdin")
        .arg("--exact")
        .arg("--nocapture")
        .env(PROBE_ENV, &key_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("child test process should spawn");

    child
        .stdin
        .as_mut()
        .expect("child stdin should be piped")
        .write_all(SENTINEL.as_bytes())
        .expect("sentinel should be writable to child stdin");

    let output = child.wait_with_output().expect("child should complete");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let remaining = stdout
        .split("REMAINING:")
        .nth(1)
        .unwrap_or("")
        .split("\ntest ")
        .next()
        .unwrap_or("");

    assert!(
        remaining.contains("SENTINEL_LINE"),
        "stdin was consumed while loading an encrypted key without a passphrase; \
         OpenSSL's interactive prompt was reached.\n  remaining stdin: {remaining:?}\n  \
         child stderr: {stderr}"
    );
    assert!(
        !stderr.contains("pass phrase") && !stdout.contains("pass phrase"),
        "a passphrase prompt was written to the child's output:\n{stderr}{stdout}"
    );

    let _ = std::fs::remove_dir_all(
        std::path::Path::new(&key_path)
            .parent()
            .expect("key path should have a parent"),
    );
}

/// Build an encrypted RSA key with the system `openssl`, returning `None` when
/// the binary is unavailable.
fn encrypted_key_fixture() -> Option<String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ssl-toolbox-stdin-probe-{nanos}"));
    std::fs::create_dir_all(&dir).ok()?;
    let key = dir.join("encrypted.key");

    let status = Command::new("openssl")
        .args(["genrsa", "-aes256", "-passout", "pass:changeit", "-out"])
        .arg(&key)
        .arg("2048")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;

    if status.success() {
        Some(key.display().to_string())
    } else {
        let _ = std::fs::remove_dir_all(&dir);
        None
    }
}

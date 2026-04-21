use openssl::ssl::SslRef;
use openssl::stack::Stack;
use openssl::x509::X509StoreContext;
use openssl::x509::store::X509StoreBuilder;
use std::sync::Once;

use crate::x509_utils::collect_peer_untrusted_chain;
use crate::{CertValidation, ValidationResult};

static OPENSSL_CERT_ENV_INIT: Once = Once::new();

/// Check if a hostname matches a pattern (supports wildcard matching).
fn hostname_matches(pattern: &str, hostname: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let hostname = hostname.to_lowercase();

    if pattern == hostname {
        return true;
    }

    // Wildcard matching: *.example.com matches foo.example.com but not foo.bar.example.com
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Wildcard must not match bare domain (*.example.com does NOT match example.com)
        if let Some(sub) = hostname.strip_suffix(&format!(".{}", suffix)) {
            // The part matched by * must not contain a dot
            return !sub.contains('.');
        }
    }

    false
}

/// Validate the peer certificate: hostname match, expiry, and chain validation.
pub fn validate_peer_cert(ssl: &SslRef, hostname: &str) -> CertValidation {
    let hostname_match = validate_hostname(ssl, hostname);
    let expiry_check = validate_expiry(ssl);
    let chain_valid = validate_chain(ssl);

    CertValidation {
        hostname_match: Some(hostname_match),
        expiry_check: Some(expiry_check),
        chain_valid: Some(chain_valid),
    }
}

fn validate_hostname(ssl: &SslRef, hostname: &str) -> ValidationResult {
    let cert = match ssl.peer_certificate() {
        Some(c) => c,
        None => {
            return ValidationResult {
                passed: false,
                message: "No peer certificate presented".to_string(),
            };
        }
    };

    // Check SANs first (RFC 6125)
    if let Some(san_ext) = cert.subject_alt_names() {
        let mut has_san_dns = false;
        for name in &san_ext {
            if let Some(dns) = name.dnsname() {
                has_san_dns = true;
                if hostname_matches(dns, hostname) {
                    return ValidationResult {
                        passed: true,
                        message: format!("matches SAN \"{}\"", dns),
                    };
                }
            }
        }
        if has_san_dns {
            return ValidationResult {
                passed: false,
                message: format!("hostname \"{}\" does not match any SAN", hostname),
            };
        }
    }

    // Fall back to CN only if no DNS SANs exist
    let subject = cert.subject_name();
    for entry in subject.entries_by_nid(openssl::nid::Nid::COMMONNAME) {
        if let Ok(cn) = entry.data().as_utf8() {
            let cn_str = cn.to_string();
            if hostname_matches(&cn_str, hostname) {
                return ValidationResult {
                    passed: true,
                    message: format!("matches CN \"{}\"", cn_str),
                };
            }
        }
    }

    ValidationResult {
        passed: false,
        message: format!("hostname \"{}\" does not match certificate", hostname),
    }
}

fn validate_expiry(ssl: &SslRef) -> ValidationResult {
    let cert = match ssl.peer_certificate() {
        Some(c) => c,
        None => {
            return ValidationResult {
                passed: false,
                message: "No peer certificate presented".to_string(),
            };
        }
    };

    let now = openssl::asn1::Asn1Time::days_from_now(0);
    let now = match now {
        Ok(t) => t,
        Err(_) => {
            return ValidationResult {
                passed: false,
                message: "Failed to get current time".to_string(),
            };
        }
    };

    let not_before = cert.not_before();
    let not_after = cert.not_after();

    // Check if cert is not yet valid
    if now.compare(not_before).map(|o| o.is_lt()).unwrap_or(false) {
        return ValidationResult {
            passed: false,
            message: format!("not yet valid (starts {})", not_before),
        };
    }

    // Check if cert has expired
    if now.compare(not_after).map(|o| o.is_gt()).unwrap_or(false) {
        return ValidationResult {
            passed: false,
            message: format!("expired (ended {})", not_after),
        };
    }

    ValidationResult {
        passed: true,
        message: format!("valid until {}", not_after),
    }
}

fn validate_chain(ssl: &SslRef) -> ValidationResult {
    let cert = match ssl.peer_certificate() {
        Some(c) => c,
        None => {
            return ValidationResult {
                passed: false,
                message: "No peer certificate presented".to_string(),
            };
        }
    };

    // The verification context expects only untrusted intermediates here. The leaf is passed
    // separately, and servers sometimes send the self-signed root as well. Feeding the trust
    // anchor back into the untrusted stack can cause false verification failures.
    let normalized_chain = collect_peer_untrusted_chain(ssl);
    let mut chain = Stack::new().unwrap();
    for cert in normalized_chain {
        let _ = chain.push(cert);
    }

    initialize_openssl_cert_env();

    // Build trust store using system default paths
    let store = match X509StoreBuilder::new() {
        Ok(mut builder) => {
            if builder.set_default_paths().is_err() {
                return ValidationResult {
                    passed: false,
                    message: "Failed to load system trust store".to_string(),
                };
            }
            builder.build()
        }
        Err(_) => {
            return ValidationResult {
                passed: false,
                message: "Failed to create X509 store".to_string(),
            };
        }
    };

    match X509StoreContext::new() {
        Ok(mut ctx) => {
            match ctx.init(&store, &cert, &chain, |ctx| {
                let verified = ctx.verify_cert()?;
                let error = ctx.error();
                let error_depth = ctx.error_depth();
                Ok((verified, error, error_depth))
            }) {
                Ok((true, _, _)) => ValidationResult {
                    passed: true,
                    message: "chain verified against system trust store".to_string(),
                },
                Ok((false, error, depth)) => ValidationResult {
                    passed: false,
                    message: format!("{} (depth {})", error.error_string(), depth),
                },
                Err(_) => ValidationResult {
                    passed: false,
                    message: "chain verification error".to_string(),
                },
            }
        }
        Err(_) => ValidationResult {
            passed: false,
            message: "Failed to create store context".to_string(),
        },
    }
}

fn initialize_openssl_cert_env() {
    OPENSSL_CERT_ENV_INIT.call_once(|| {
        // OpenSSL in the vendored Rust build does not automatically discover the platform trust
        // store everywhere. Probe once and populate SSL_CERT_FILE / SSL_CERT_DIR for this process.
        unsafe {
            let _ = openssl_probe::try_init_openssl_env_vars();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hostname_matches_exact() {
        assert!(hostname_matches("example.com", "example.com"));
        assert!(hostname_matches("Example.COM", "example.com"));
    }

    #[test]
    fn test_hostname_matches_wildcard() {
        assert!(hostname_matches("*.example.com", "foo.example.com"));
        assert!(!hostname_matches("*.example.com", "example.com"));
        assert!(!hostname_matches("*.example.com", "foo.bar.example.com"));
    }

    #[test]
    fn test_hostname_no_match() {
        assert!(!hostname_matches("other.com", "example.com"));
    }
}

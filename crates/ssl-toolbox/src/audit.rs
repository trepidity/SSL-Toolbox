use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use ssl_toolbox_core::{CertValidation, TlsCheckResult};

use crate::workflow::ActionKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationAuditStatus {
    Success,
    Failure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationAuditEntry {
    pub timestamp_secs: u64,
    pub timestamp_utc: String,
    pub kind: ActionKind,
    pub host: String,
    pub port: u16,
    pub certificate_validation_requested: bool,
    pub full_scan: bool,
    pub status: ValidationAuditStatus,
    pub result: Option<ValidationSnapshot>,
    pub error: Option<String>,
    pub comparison: ValidationComparison,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationSnapshot {
    pub negotiated_protocol: String,
    pub negotiated_cipher: String,
    pub negotiated_cipher_bits: i32,
    pub cert_chain_len: usize,
    pub leaf_common_name: Option<String>,
    pub leaf_issuer: Option<String>,
    pub leaf_serial_number: Option<String>,
    pub leaf_not_before: Option<String>,
    pub leaf_not_after: Option<String>,
    pub leaf_sha256_fingerprint: Option<String>,
    pub leaf_sans: Vec<String>,
    pub supported_tls_versions: Vec<String>,
    pub cipher_support_by_protocol: Vec<ProtocolCipherSupport>,
    pub validation: Option<ValidationSnapshotSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolCipherSupport {
    pub protocol: String,
    pub supported_cipher_count: usize,
    pub tested_cipher_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationSnapshotSummary {
    pub hostname_match: Option<bool>,
    pub hostname_message: Option<String>,
    pub expiry_check: Option<bool>,
    pub expiry_message: Option<String>,
    pub chain_valid: Option<bool>,
    pub chain_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationComparison {
    pub previous_timestamp_utc: Option<String>,
    pub changes: Vec<String>,
}

pub fn find_previous_entry<'a>(
    entries: &'a [ValidationAuditEntry],
    kind: ActionKind,
    host: &str,
    port: u16,
) -> Option<&'a ValidationAuditEntry> {
    entries
        .iter()
        .rev()
        .find(|entry| entry.kind == kind && entry.host == host && entry.port == port)
}

pub fn build_success_entry(
    kind: ActionKind,
    host: &str,
    port: u16,
    certificate_validation_requested: bool,
    full_scan: bool,
    result: &TlsCheckResult,
    previous: Option<&ValidationAuditEntry>,
) -> ValidationAuditEntry {
    let timestamp_secs = now_timestamp_secs();
    let current = snapshot_from_result(result);
    let comparison = build_comparison(
        previous,
        ValidationAuditStatus::Success,
        Some(&current),
        None,
        certificate_validation_requested,
        full_scan,
    );

    ValidationAuditEntry {
        timestamp_secs,
        timestamp_utc: format_timestamp_utc(timestamp_secs),
        kind,
        host: host.to_string(),
        port,
        certificate_validation_requested,
        full_scan,
        status: ValidationAuditStatus::Success,
        result: Some(current),
        error: None,
        comparison,
    }
}

pub fn build_failure_entry(
    kind: ActionKind,
    host: &str,
    port: u16,
    certificate_validation_requested: bool,
    full_scan: bool,
    error: impl Into<String>,
    previous: Option<&ValidationAuditEntry>,
) -> ValidationAuditEntry {
    let timestamp_secs = now_timestamp_secs();
    let error = error.into();
    let comparison = build_comparison(
        previous,
        ValidationAuditStatus::Failure,
        None,
        Some(&error),
        certificate_validation_requested,
        full_scan,
    );

    ValidationAuditEntry {
        timestamp_secs,
        timestamp_utc: format_timestamp_utc(timestamp_secs),
        kind,
        host: host.to_string(),
        port,
        certificate_validation_requested,
        full_scan,
        status: ValidationAuditStatus::Failure,
        result: None,
        error: Some(error),
        comparison,
    }
}

pub fn format_timestamp_utc(timestamp_secs: u64) -> String {
    let days = (timestamp_secs / 86_400) as i64;
    let seconds_of_day = timestamp_secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn now_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}

fn civil_from_days(days_since_unix_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }

    (year as i32, month as u32, day as u32)
}

fn snapshot_from_result(result: &TlsCheckResult) -> ValidationSnapshot {
    let leaf = result.cert_chain.first();
    ValidationSnapshot {
        negotiated_protocol: result.cipher.protocol.clone(),
        negotiated_cipher: result.cipher.name.clone(),
        negotiated_cipher_bits: result.cipher.bits,
        cert_chain_len: result.cert_chain.len(),
        leaf_common_name: leaf.map(|cert| cert.common_name.clone()),
        leaf_issuer: leaf.map(|cert| cert.issuer.clone()),
        leaf_serial_number: leaf.map(|cert| cert.serial_number.clone()),
        leaf_not_before: leaf.map(|cert| cert.not_before.clone()),
        leaf_not_after: leaf.map(|cert| cert.not_after.clone()),
        leaf_sha256_fingerprint: leaf.map(|cert| cert.sha256_fingerprint.clone()),
        leaf_sans: leaf.map(|cert| cert.sans.clone()).unwrap_or_default(),
        supported_tls_versions: result
            .version_support
            .iter()
            .filter(|probe| probe.supported)
            .map(|probe| probe.label.clone())
            .collect(),
        cipher_support_by_protocol: result
            .cipher_scan
            .iter()
            .map(|scan| ProtocolCipherSupport {
                protocol: scan.protocol.clone(),
                supported_cipher_count: scan.supported_ciphers.len(),
                tested_cipher_count: scan.tested_cipher_count,
            })
            .collect(),
        validation: result.validation.as_ref().map(validation_summary),
    }
}

fn validation_summary(validation: &CertValidation) -> ValidationSnapshotSummary {
    ValidationSnapshotSummary {
        hostname_match: validation.hostname_match.as_ref().map(|item| item.passed),
        hostname_message: validation
            .hostname_match
            .as_ref()
            .map(|item| item.message.clone()),
        expiry_check: validation.expiry_check.as_ref().map(|item| item.passed),
        expiry_message: validation
            .expiry_check
            .as_ref()
            .map(|item| item.message.clone()),
        chain_valid: validation.chain_valid.as_ref().map(|item| item.passed),
        chain_message: validation
            .chain_valid
            .as_ref()
            .map(|item| item.message.clone()),
    }
}

fn build_comparison(
    previous: Option<&ValidationAuditEntry>,
    current_status: ValidationAuditStatus,
    current_result: Option<&ValidationSnapshot>,
    current_error: Option<&str>,
    certificate_validation_requested: bool,
    full_scan: bool,
) -> ValidationComparison {
    let Some(previous) = previous else {
        return ValidationComparison {
            previous_timestamp_utc: None,
            changes: vec!["First recorded validation for this endpoint.".to_string()],
        };
    };

    let mut changes = Vec::new();
    if previous.status != current_status {
        changes.push(format!(
            "Result changed from {} to {}.",
            status_label(previous.status),
            status_label(current_status)
        ));
    }
    if previous.certificate_validation_requested != certificate_validation_requested {
        changes.push(format!(
            "Certificate validation request changed from {} to {}.",
            bool_label(previous.certificate_validation_requested),
            bool_label(certificate_validation_requested)
        ));
    }
    if previous.full_scan != full_scan {
        changes.push(format!(
            "Full scan setting changed from {} to {}.",
            bool_label(previous.full_scan),
            bool_label(full_scan)
        ));
    }

    match (&previous.result, current_result) {
        (Some(previous_result), Some(current_result)) => {
            compare_successful_results(previous_result, current_result, &mut changes);
        }
        (None, Some(_)) => {
            if let Some(error) = previous.error.as_deref() {
                changes.push(format!(
                    "Previous run failed with: {}",
                    squash_whitespace(error)
                ));
            }
        }
        (Some(_), None) => {
            if let Some(error) = current_error {
                changes.push(format!(
                    "Current run failed with: {}",
                    squash_whitespace(error)
                ));
            }
        }
        (None, None) => {
            if previous.error.as_deref() != current_error {
                changes.push(format!(
                    "Failure reason changed from '{}' to '{}'.",
                    squash_whitespace(previous.error.as_deref().unwrap_or("unknown")),
                    squash_whitespace(current_error.unwrap_or("unknown"))
                ));
            }
        }
    }

    if changes.is_empty() {
        changes.push(
            "No material changes detected compared with the previous recorded run.".to_string(),
        );
    }

    ValidationComparison {
        previous_timestamp_utc: Some(previous.timestamp_utc.clone()),
        changes,
    }
}

fn compare_successful_results(
    previous: &ValidationSnapshot,
    current: &ValidationSnapshot,
    changes: &mut Vec<String>,
) {
    compare_option(
        "Negotiated protocol changed",
        previous.negotiated_protocol.as_str(),
        current.negotiated_protocol.as_str(),
        changes,
    );
    compare_option(
        "Negotiated cipher changed",
        previous.negotiated_cipher.as_str(),
        current.negotiated_cipher.as_str(),
        changes,
    );
    if previous.negotiated_cipher_bits != current.negotiated_cipher_bits {
        changes.push(format!(
            "Cipher strength changed from {} bits to {} bits.",
            previous.negotiated_cipher_bits, current.negotiated_cipher_bits
        ));
    }
    if previous.cert_chain_len != current.cert_chain_len {
        changes.push(format!(
            "Certificate chain length changed from {} to {}.",
            previous.cert_chain_len, current.cert_chain_len
        ));
    }
    compare_optional_field(
        "Leaf certificate common name changed",
        previous.leaf_common_name.as_deref(),
        current.leaf_common_name.as_deref(),
        changes,
    );
    compare_optional_field(
        "Leaf certificate issuer changed",
        previous.leaf_issuer.as_deref(),
        current.leaf_issuer.as_deref(),
        changes,
    );
    compare_optional_field(
        "Leaf certificate serial number changed",
        previous.leaf_serial_number.as_deref(),
        current.leaf_serial_number.as_deref(),
        changes,
    );
    compare_optional_field(
        "Leaf certificate validity start changed",
        previous.leaf_not_before.as_deref(),
        current.leaf_not_before.as_deref(),
        changes,
    );
    compare_optional_field(
        "Leaf certificate expiry changed",
        previous.leaf_not_after.as_deref(),
        current.leaf_not_after.as_deref(),
        changes,
    );
    compare_optional_field(
        "Leaf certificate SHA256 fingerprint changed",
        previous.leaf_sha256_fingerprint.as_deref(),
        current.leaf_sha256_fingerprint.as_deref(),
        changes,
    );

    compare_set(
        "Leaf certificate SANs",
        &previous.leaf_sans,
        &current.leaf_sans,
        changes,
    );
    compare_set(
        "Supported TLS versions",
        &previous.supported_tls_versions,
        &current.supported_tls_versions,
        changes,
    );
    compare_cipher_support(
        &previous.cipher_support_by_protocol,
        &current.cipher_support_by_protocol,
        changes,
    );
    compare_validation_summary(
        previous.validation.as_ref(),
        current.validation.as_ref(),
        changes,
    );
}

fn compare_option(label: &str, previous: &str, current: &str, changes: &mut Vec<String>) {
    if previous != current {
        changes.push(format!("{label}: '{previous}' -> '{current}'."));
    }
}

fn compare_optional_field(
    label: &str,
    previous: Option<&str>,
    current: Option<&str>,
    changes: &mut Vec<String>,
) {
    if previous != current {
        changes.push(format!(
            "{label}: '{}' -> '{}'.",
            previous.unwrap_or("none"),
            current.unwrap_or("none")
        ));
    }
}

fn compare_set(label: &str, previous: &[String], current: &[String], changes: &mut Vec<String>) {
    let previous = previous.iter().cloned().collect::<BTreeSet<_>>();
    let current = current.iter().cloned().collect::<BTreeSet<_>>();
    let added = current.difference(&previous).cloned().collect::<Vec<_>>();
    let removed = previous.difference(&current).cloned().collect::<Vec<_>>();
    if added.is_empty() && removed.is_empty() {
        return;
    }

    let mut parts = Vec::new();
    if !added.is_empty() {
        parts.push(format!("added {}", added.join(", ")));
    }
    if !removed.is_empty() {
        parts.push(format!("removed {}", removed.join(", ")));
    }
    changes.push(format!("{label} changed: {}.", parts.join("; ")));
}

fn compare_cipher_support(
    previous: &[ProtocolCipherSupport],
    current: &[ProtocolCipherSupport],
    changes: &mut Vec<String>,
) {
    let protocols = previous
        .iter()
        .map(|item| item.protocol.clone())
        .chain(current.iter().map(|item| item.protocol.clone()))
        .collect::<BTreeSet<_>>();

    for protocol in protocols {
        let previous = previous.iter().find(|item| item.protocol == protocol);
        let current = current.iter().find(|item| item.protocol == protocol);
        if previous == current {
            continue;
        }

        let previous_label = previous
            .map(|item| {
                format!(
                    "{}/{}",
                    item.supported_cipher_count, item.tested_cipher_count
                )
            })
            .unwrap_or_else(|| "none".to_string());
        let current_label = current
            .map(|item| {
                format!(
                    "{}/{}",
                    item.supported_cipher_count, item.tested_cipher_count
                )
            })
            .unwrap_or_else(|| "none".to_string());
        changes.push(format!(
            "Full scan cipher support for {} changed: {} -> {}.",
            protocol, previous_label, current_label
        ));
    }
}

fn compare_validation_summary(
    previous: Option<&ValidationSnapshotSummary>,
    current: Option<&ValidationSnapshotSummary>,
    changes: &mut Vec<String>,
) {
    if previous.is_none() && current.is_none() {
        return;
    }
    if previous.is_none() || current.is_none() {
        changes.push(format!(
            "Certificate validation summary changed from {} to {}.",
            validation_summary_presence(previous),
            validation_summary_presence(current)
        ));
        return;
    }

    let previous = previous.expect("previous summary");
    let current = current.expect("current summary");
    compare_optional_bool(
        "Hostname validation result changed",
        previous.hostname_match,
        current.hostname_match,
        changes,
    );
    compare_optional_bool(
        "Expiry validation result changed",
        previous.expiry_check,
        current.expiry_check,
        changes,
    );
    compare_optional_bool(
        "Chain validation result changed",
        previous.chain_valid,
        current.chain_valid,
        changes,
    );
    compare_optional_field(
        "Hostname validation detail changed",
        previous.hostname_message.as_deref(),
        current.hostname_message.as_deref(),
        changes,
    );
    compare_optional_field(
        "Expiry validation detail changed",
        previous.expiry_message.as_deref(),
        current.expiry_message.as_deref(),
        changes,
    );
    compare_optional_field(
        "Chain validation detail changed",
        previous.chain_message.as_deref(),
        current.chain_message.as_deref(),
        changes,
    );
}

fn compare_optional_bool(
    label: &str,
    previous: Option<bool>,
    current: Option<bool>,
    changes: &mut Vec<String>,
) {
    if previous != current {
        changes.push(format!(
            "{label}: '{}' -> '{}'.",
            optional_bool_label(previous),
            optional_bool_label(current)
        ));
    }
}

fn validation_summary_presence(summary: Option<&ValidationSnapshotSummary>) -> &'static str {
    if summary.is_some() {
        "present"
    } else {
        "not present"
    }
}

fn optional_bool_label(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "pass",
        Some(false) => "fail",
        None => "not-run",
    }
}

fn status_label(status: ValidationAuditStatus) -> &'static str {
    match status {
        ValidationAuditStatus::Success => "success",
        ValidationAuditStatus::Failure => "failure",
    }
}

fn bool_label(value: bool) -> &'static str {
    if value { "enabled" } else { "disabled" }
}

fn squash_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use ssl_toolbox_core::{
        CertDetails, CertValidation, CipherInfo, TlsCheckResult, TlsCipherScanResult,
        TlsVersionProbeResult, ValidationResult,
    };

    use super::*;

    fn sample_result() -> TlsCheckResult {
        TlsCheckResult {
            host: "ldap.example.com".to_string(),
            port: 636,
            cipher: CipherInfo {
                name: "TLS_AES_256_GCM_SHA384".to_string(),
                bits: 256,
                protocol: "TLSv1.3".to_string(),
            },
            cert_chain: vec![CertDetails {
                common_name: "ldap.example.com".to_string(),
                sans: vec![
                    "ldap.example.com".to_string(),
                    "ldap.internal.example.com".to_string(),
                ],
                not_before: "2026-01-01T00:00:00Z".to_string(),
                not_after: "2027-01-01T00:00:00Z".to_string(),
                issuer: "Example Issuer".to_string(),
                signature_algorithm: "sha256WithRSAEncryption".to_string(),
                public_key_bits: 2048,
                serial_number: "01".to_string(),
                sha1_fingerprint: "sha1".to_string(),
                sha256_fingerprint: "sha256-a".to_string(),
            }],
            cert_chain_pem: Vec::new(),
            version_support: vec![
                TlsVersionProbeResult {
                    label: "TLS 1.2".to_string(),
                    supported: true,
                },
                TlsVersionProbeResult {
                    label: "TLS 1.3".to_string(),
                    supported: true,
                },
            ],
            cipher_scan: vec![TlsCipherScanResult {
                protocol: "TLS 1.2".to_string(),
                tested_cipher_count: 10,
                supported_ciphers: vec![CipherInfo {
                    name: "ECDHE-RSA-AES256-GCM-SHA384".to_string(),
                    bits: 256,
                    protocol: "TLS 1.2".to_string(),
                }],
            }],
            validation: Some(CertValidation {
                hostname_match: Some(ValidationResult {
                    passed: true,
                    message: "hostname matches".to_string(),
                }),
                expiry_check: Some(ValidationResult {
                    passed: true,
                    message: "certificate is valid".to_string(),
                }),
                chain_valid: Some(ValidationResult {
                    passed: true,
                    message: "chain verified".to_string(),
                }),
            }),
        }
    }

    #[test]
    fn formats_unix_epoch_as_utc() {
        assert_eq!(format_timestamp_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_timestamp_utc(1_704_067_200), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn comparison_reports_certificate_and_tls_changes() {
        let previous = build_success_entry(
            ActionKind::VerifyLdaps,
            "ldap.example.com",
            636,
            true,
            true,
            &sample_result(),
            None,
        );

        let mut current_result = sample_result();
        current_result.cipher.protocol = "TLSv1.2".to_string();
        current_result.cipher.name = "ECDHE-RSA-AES256-GCM-SHA384".to_string();
        current_result.cert_chain[0].sha256_fingerprint = "sha256-b".to_string();
        current_result.cert_chain[0]
            .sans
            .push("ldap-dr.example.com".to_string());
        current_result.version_support.pop();
        current_result.cipher_scan[0]
            .supported_ciphers
            .push(CipherInfo {
                name: "ECDHE-RSA-AES128-GCM-SHA256".to_string(),
                bits: 128,
                protocol: "TLS 1.2".to_string(),
            });

        let current = build_success_entry(
            ActionKind::VerifyLdaps,
            "ldap.example.com",
            636,
            true,
            true,
            &current_result,
            Some(&previous),
        );

        assert!(
            current
                .comparison
                .changes
                .iter()
                .any(|item| item.contains("Negotiated protocol changed"))
        );
        assert!(
            current
                .comparison
                .changes
                .iter()
                .any(|item| item.contains("Leaf certificate SHA256 fingerprint changed"))
        );
        assert!(
            current
                .comparison
                .changes
                .iter()
                .any(|item| item.contains("Leaf certificate SANs changed"))
        );
        assert!(
            current
                .comparison
                .changes
                .iter()
                .any(|item| item.contains("Supported TLS versions changed"))
        );
    }

    #[test]
    fn comparison_reports_failure_transition() {
        let previous = build_failure_entry(
            ActionKind::VerifyLdaps,
            "ldap.example.com",
            636,
            true,
            false,
            "TCP connection timed out",
            None,
        );

        let current = build_success_entry(
            ActionKind::VerifyLdaps,
            "ldap.example.com",
            636,
            true,
            false,
            &sample_result(),
            Some(&previous),
        );

        assert!(
            current
                .comparison
                .changes
                .iter()
                .any(|item| item.contains("Result changed from failure to success"))
        );
        assert!(
            current
                .comparison
                .changes
                .iter()
                .any(|item| item.contains("Previous run failed with"))
        );
    }
}

use anyhow::{Context, Result};
use openssl::stack::Stack;
use openssl::x509::{GeneralName, X509, X509Req};
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use crate::{ConfigInputs, ConfigSummary, SanKind, SanName};

/// Read an existing OpenSSL config far enough to describe it.
///
/// Never fails and never rewrites: an unparseable config still returns a summary
/// (with warnings) so the editor can always open the file.
///
/// Section names are *followed*, not assumed. `[req] distinguished_name` and
/// `subjectAltName = @…` may point anywhere, and a config that spells its DN
/// section `[dn]` is perfectly valid OpenSSL — reading only the conventional
/// names would report "no common name" on a file that plainly has one.
pub fn summarize_conf(text: &str, base_dir: Option<&Path>) -> ConfigSummary {
    let parsed = parse_config(text, base_dir);
    let mut summary = ConfigSummary {
        sections: parsed.named_sections(),
        warnings: parsed.warnings.clone(),
        ..Default::default()
    };

    let req = parsed.section("req");

    let dn_name = req
        .and_then(|s| s.get("distinguished_name"))
        .unwrap_or("req_distinguished_name")
        .to_string();
    let ext_name = req.and_then(|s| s.get("req_extensions")).map(str::to_string);

    if let Some(dn) = parsed.section(&dn_name) {
        summary.common_name = dn.dn_attribute(&["cn", "commonname"]);
        summary.country = dn.dn_attribute(&["c", "countryname"]);
        summary.state = dn.dn_attribute(&["st", "stateorprovincename"]);
        summary.locality = dn.dn_attribute(&["l", "localityname"]);
        summary.organization = dn.dn_attribute(&["o", "organizationname"]);
        summary.org_unit = dn.dn_attribute(&["ou", "organizationalunitname"]);
        summary.email = dn.dn_attribute(&["emailaddress", "email", "e"]);
    }

    summary.key_size = req
        .and_then(|s| s.get("default_bits"))
        .and_then(|bits| bits.parse::<u32>().ok());

    // The SAN section is named by whichever extension section is in force.
    let ext_section = ext_name
        .as_deref()
        .and_then(|name| parsed.section(name));
    if let Some(ext) = ext_section {
        summary.extended_key_usage = ext.get("extendedKeyUsage").map(str::to_string);
    }
    let san_name = ext_section
        .and_then(|s| s.get("subjectAltName"))
        .and_then(|value| value.strip_prefix('@'))
        .unwrap_or("alt_names")
        .to_string();

    let san_section = parsed.section(&san_name);
    // Keys in `[alt_names]` that are not a SAN type at all — a typo like `DSN.1`
    // silently contributes nothing to the certificate, so it is called out.
    let mut unknown_sans: Vec<String> = Vec::new();
    // Sections a `dirName` SAN points at are read, so they must not later be
    // reported as unread.
    let mut dir_sections: Vec<String> = Vec::new();
    if let Some(sans) = san_section {
        for (key, value) in &sans.entries {
            let type_key = key.split('.').next().unwrap_or("");
            match SanKind::from_config_key(type_key) {
                Some(SanKind::DirName) => {
                    dir_sections.push(value.clone());
                    // The value names a section holding a DN. Resolve it so the
                    // reader shows the actual name rather than a bare reference.
                    let resolved = parsed
                        .section(value)
                        .map(|section| {
                            section
                                .entries
                                .iter()
                                .map(|(k, v)| format!("{k}={v}"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .filter(|dn| !dn.is_empty());
                    match resolved {
                        Some(dn) => summary.sans.push(SanName::new(SanKind::DirName, dn)),
                        None => {
                            summary.sans.push(SanName::new(SanKind::DirName, value.clone()));
                            summary.warnings.push(format!(
                                "{key} points at section [{value}], which this config does not \
                                 define — OpenSSL will reject it."
                            ));
                        }
                    }
                }
                Some(kind) => summary.sans.push(SanName::new(kind, value.clone())),
                None => unknown_sans.push(format!("{key} = {value}")),
            }
        }
    }

    // Warnings: everything an operator would want flagged before signing.
    let mut modelled = vec!["req".to_string(), dn_name, san_name.clone()];
    modelled.extend(ext_name);
    modelled.extend(dir_sections);

    let unmodelled: Vec<&str> = parsed
        .sections
        .iter()
        .filter(|s| s.name != DEFAULT_SECTION)
        .map(|s| s.name.as_str())
        .filter(|name| !modelled.iter().any(|m| m == name))
        .collect();
    if !unmodelled.is_empty() {
        summary.warnings.push(format!(
            "Not read by this tool, preserved as written: {}",
            unmodelled.join(", ")
        ));
    }

    match &summary.common_name {
        None => summary
            .warnings
            .push("No CN found — this config will not produce a usable subject.".to_string()),
        Some(cn)
            if !summary
                .sans
                .iter()
                .any(|san| san.kind == SanKind::Dns && &san.value == cn) =>
        {
            summary.warnings.push(format!(
                "CN {cn} is not in the SAN list. Current TLS clients match on SANs only, \
                 so a certificate from this config will fail hostname verification for {cn}."
            ));
        }
        Some(_) => {}
    }

    if san_section.is_none() {
        summary.warnings.push(format!(
            "No [{san_name}] section — the request will carry no subject alternative names."
        ));
    }

    if !unknown_sans.is_empty() {
        summary.warnings.push(format!(
            "Not a recognised SAN type, so it will not appear in the certificate: {}",
            unknown_sans.join(", ")
        ));
    }

    summary
}

/// One section of an OpenSSL config, entries kept in file order.
struct IniSection {
    name: String,
    entries: Vec<(String, String)>,
}

impl IniSection {
    /// Last assignment wins, matching how OpenSSL resolves a repeated key.
    fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Read one subject attribute, accepting every spelling OpenSSL does.
    ///
    /// Two syntaxes have to be handled or the subject reads as empty on configs
    /// that plainly specify one:
    ///
    /// - **Short and long names are interchangeable.** `CN` and `commonName` are
    ///   the same attribute; `openssl req` writes the long form, and so do most
    ///   hand-maintained configs.
    /// - **An `N.` prefix orders repeated attributes.** `0.organizationName` and
    ///   `1.organizationName` are two values of *one* attribute, both of which end
    ///   up in the subject, so both are reported (joined) rather than one hiding
    ///   the other. A repeat of the *same* raw key is an override, last one wins.
    fn dn_attribute(&self, aliases: &[&str]) -> Option<String> {
        let mut found: Vec<(&str, &str)> = Vec::new();

        for (key, value) in &self.entries {
            let bare = key.split_once('.').map_or(key.as_str(), |(prefix, rest)| {
                // Only a numeric prefix is ordering syntax; anything else is part
                // of the name and must not be stripped.
                if prefix.chars().all(|c| c.is_ascii_digit()) && !prefix.is_empty() {
                    rest
                } else {
                    key.as_str()
                }
            });

            if !aliases.contains(&bare.to_ascii_lowercase().as_str()) {
                continue;
            }

            match found.iter_mut().find(|(seen, _)| *seen == key.as_str()) {
                Some(slot) => slot.1 = value,
                None => found.push((key, value)),
            }
        }

        if found.is_empty() {
            return None;
        }
        Some(
            found
                .iter()
                .map(|(_, value)| *value)
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

/// The default (unnamed) section, per `config(5)`: entries above the first
/// `[section]` header live here, and unqualified `$name` lookups fall back to it.
const DEFAULT_SECTION: &str = "";

/// How deep `.include` may nest before we stop. A config that includes itself is
/// a mistake, not a reason to recurse until the stack dies.
const MAX_INCLUDE_DEPTH: usize = 8;

struct ParsedConfig {
    sections: Vec<IniSection>,
    warnings: Vec<String>,
}

impl ParsedConfig {
    fn section(&self, name: &str) -> Option<&IniSection> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Section names in file order, for display. The default section is skipped
    /// when empty (an empty `[]` would be noise) and labelled when it is not,
    /// because it has no name of its own to show.
    fn named_sections(&self) -> Vec<String> {
        self.sections
            .iter()
            .filter(|s| s.name != DEFAULT_SECTION || !s.entries.is_empty())
            .map(|s| {
                if s.name == DEFAULT_SECTION {
                    "(default)".to_string()
                } else {
                    s.name.clone()
                }
            })
            .collect()
    }
}

/// Parse the OpenSSL configuration format (`config(5)`).
///
/// This is a real tokenizer rather than a line splitter, because the format has
/// several constructs that defeat splitting:
///
/// - **A default section.** Entries above the first `[section]` belong to it and
///   are the fallback for unqualified `$name` lookups.
/// - **Quoting.** `"…"` allows escapes and `$` expansion; `'…'` is literal. A `#`
///   inside either is data, not the start of a comment.
/// - **Escapes.** `\` escapes the next character, `\n`/`\r`/`\t`/`\b` are
///   recognised, and a trailing `\` continues the logical line.
/// - **Variable expansion.** `$name`, `${name}`, `$section::name`,
///   `${section::name}`, and `$ENV::name`. Values are expanded as they are read,
///   so only already-defined entries are visible — matching OpenSSL.
/// - **Directives.** `.include` pulls in another file; `.pragma` changes parsing.
///
/// `base_dir` is where relative `.include` paths resolve from — the directory of
/// the file being read. `None` disables includes.
fn parse_config(text: &str, base_dir: Option<&Path>) -> ParsedConfig {
    let mut parsed = ParsedConfig {
        sections: vec![IniSection {
            name: DEFAULT_SECTION.to_string(),
            entries: Vec::new(),
        }],
        warnings: Vec::new(),
    };
    parse_into(text, base_dir, 0, &mut parsed);
    parsed
}

fn parse_into(text: &str, base_dir: Option<&Path>, depth: usize, out: &mut ParsedConfig) {
    let mut current = DEFAULT_SECTION.to_string();

    for line in logical_lines(text) {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Directives come before anything else: a leading `.` is never a name.
        if let Some(directive) = trimmed.strip_prefix('.') {
            handle_directive(directive, base_dir, depth, out);
            continue;
        }

        if trimmed.starts_with('[') {
            match trimmed.find(']') {
                Some(end) => {
                    current = trimmed[1..end].trim().to_string();
                    if out.section(&current).is_none() {
                        out.sections.push(IniSection {
                            name: current.clone(),
                            entries: Vec::new(),
                        });
                    }
                }
                None => out.warnings.push(format!(
                    "Unterminated section header {trimmed:?} — OpenSSL will reject this file."
                )),
            }
            continue;
        }

        // Split on the first `=` that is not quoted or escaped.
        let Some(split) = find_unquoted(trimmed, '=') else {
            out.warnings.push(format!(
                "Line {trimmed:?} is neither a section, a directive, nor name=value."
            ));
            continue;
        };

        let name = unquote(&trimmed[..split], &current, out, false).trim().to_string();
        let value = unquote(&trimmed[split + 1..], &current, out, true);
        if name.is_empty() {
            continue;
        }

        let target = current.clone();
        if out.section(&target).is_none() {
            out.sections.push(IniSection {
                name: target.clone(),
                entries: Vec::new(),
            });
        }
        if let Some(section) = out.sections.iter_mut().find(|s| s.name == target) {
            section.entries.push((name, value));
        }
    }
}

fn handle_directive(directive: &str, base_dir: Option<&Path>, depth: usize, out: &mut ParsedConfig) {
    // `.include file` and `.include=file` are both accepted by OpenSSL.
    let (word, rest) = match directive.find([' ', '\t', '=']) {
        Some(at) => (&directive[..at], directive[at + 1..].trim()),
        None => (directive, ""),
    };

    match word {
        "include" => {
            let target = rest.trim_matches('"').trim();
            if target.is_empty() {
                out.warnings
                    .push(".include with no file name.".to_string());
                return;
            }
            if depth >= MAX_INCLUDE_DEPTH {
                out.warnings.push(format!(
                    ".include nesting deeper than {MAX_INCLUDE_DEPTH} at {target:?} — stopped."
                ));
                return;
            }
            let Some(base) = base_dir else {
                out.warnings.push(format!(
                    ".include {target:?} was not followed because this config was read \
                     without a directory to resolve it against."
                ));
                return;
            };
            let path = {
                let candidate = Path::new(target);
                if candidate.is_absolute() {
                    candidate.to_path_buf()
                } else {
                    base.join(candidate)
                }
            };
            match fs::read_to_string(&path) {
                Ok(included) => {
                    let nested_base = path.parent().map(Path::to_path_buf);
                    parse_into(&included, nested_base.as_deref(), depth + 1, out);
                }
                Err(error) => out.warnings.push(format!(
                    ".include {target:?} could not be read ({error}), so anything it defines \
                     is missing from this reading."
                )),
            }
        }
        "pragma" => out.warnings.push(format!(
            ".pragma {rest:?} is recognised but not applied by this reader — if it changes \
             parsing, what is shown here may differ from what OpenSSL sees."
        )),
        other => out.warnings.push(format!(
            "Unknown directive .{other} — ignored by this reader."
        )),
    }
}

/// Join physical lines ending in an unescaped `\` into one logical line.
fn logical_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut pending = String::new();

    for raw in text.lines() {
        // A trailing `\` continues the line; `\\` is an escaped backslash and does
        // not, so count how many trail.
        let trailing = raw.chars().rev().take_while(|c| *c == '\\').count();
        if trailing % 2 == 1 {
            pending.push_str(&raw[..raw.len() - 1]);
        } else {
            pending.push_str(raw);
            lines.push(std::mem::take(&mut pending));
        }
    }
    if !pending.is_empty() {
        lines.push(pending);
    }
    lines
}

/// Byte index of the first unquoted, unescaped occurrence of `needle`.
fn find_unquoted(text: &str, needle: char) -> Option<usize> {
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for (index, character) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if quote != Some('\'') => escaped = true,
            '"' | '\'' if quote.is_none() => quote = Some(character),
            c if Some(c) == quote => quote = None,
            c if c == needle && quote.is_none() => return Some(index),
            '#' if quote.is_none() => return None,
            _ => {}
        }
    }
    None
}

/// Resolve one side of a `name = value` line: strip comments, apply quoting and
/// escapes, and expand variables.
fn unquote(
    raw: &str,
    current_section: &str,
    out: &mut ParsedConfig,
    expand_vars: bool,
) -> String {
    // Whitespace around the whole value is insignificant, so it is removed before
    // tokenizing — otherwise the space in `O = "Example"` before the quote would be
    // copied into the value, which quoting then protects from being trimmed away.
    let mut result = String::new();
    let mut chars = raw.trim().chars().peekable();
    let mut quote: Option<char> = None;
    // Whitespace is only significant when it came from inside quotes or from an
    // escape. `CN = host # note` must not keep the space before the comment, while
    // `O = " padded "` must keep both. Tracking the last position worth keeping is
    // simpler than deciding after the fact.
    let mut keep_len = 0usize;

    while let Some(character) = chars.next() {
        let significant_whitespace = quote.is_some();
        match character {
            // Single quotes are literal, so no escape processing inside them.
            '\\' if quote != Some('\'') => {
                match chars.next() {
                    Some('n') => result.push('\n'),
                    Some('r') => result.push('\r'),
                    Some('t') => result.push('\t'),
                    Some('b') => result.push('\u{8}'),
                    Some(other) => result.push(other),
                    None => {}
                }
                // An escaped character is always intentional, whitespace included.
                keep_len = result.len();
            }
            '"' | '\'' if quote.is_none() => quote = Some(character),
            c if Some(c) == quote => quote = None,
            // A comment can only start outside quotes.
            '#' if quote.is_none() => break,
            '$' if quote != Some('\'') && expand_vars => {
                result.push_str(&expand(&mut chars, current_section, out));
                keep_len = result.len();
            }
            other => {
                result.push(other);
                if significant_whitespace || !other.is_whitespace() {
                    keep_len = result.len();
                }
            }
        }
    }

    result.truncate(keep_len);
    result
}

/// Expand a `$…` reference. The `$` has already been consumed.
fn expand(
    chars: &mut std::iter::Peekable<std::str::Chars>,
    current_section: &str,
    out: &mut ParsedConfig,
) -> String {
    let braced = chars.peek() == Some(&'{');
    if braced {
        chars.next();
    }

    let mut token = String::new();
    while let Some(&next) = chars.peek() {
        // Unbraced names are alphanumerics, `_`, and the `::` section qualifier —
        // matching OpenSSL. `.` must terminate, or `$host.$domain` reads the name
        // as `host.` and resolves nothing. `${…}` runs to the closing brace.
        let part_of_name = next.is_alphanumeric() || matches!(next, '_' | ':');
        if braced && next == '}' {
            chars.next();
            break;
        }
        if !braced && !part_of_name {
            break;
        }
        token.push(next);
        chars.next();
    }

    let (section, name) = match token.split_once("::") {
        Some((section, name)) => (Some(section.to_string()), name.to_string()),
        None => (None, token.clone()),
    };

    // `$ENV::NAME` reaches the process environment rather than the file.
    if section.as_deref() == Some("ENV") {
        return match std::env::var(&name) {
            Ok(value) => value,
            Err(_) => {
                out.warnings.push(format!(
                    "$ENV::{name} is not set in this environment, so it expanded to nothing."
                ));
                String::new()
            }
        };
    }

    // Qualified: that section only. Unqualified: the current section, then the
    // default section — the lookup order `config(5)` specifies.
    let lookup = |parsed: &ParsedConfig| -> Option<String> {
        match &section {
            Some(name_of_section) => parsed
                .section(name_of_section)
                .and_then(|s| s.get(&name))
                .map(str::to_string),
            None => parsed
                .section(current_section)
                .and_then(|s| s.get(&name))
                .or_else(|| parsed.section(DEFAULT_SECTION).and_then(|s| s.get(&name)))
                .map(str::to_string),
        }
    };

    match lookup(out) {
        Some(value) => value,
        None => {
            let shown = match &section {
                Some(s) => format!("${s}::{name}"),
                None => format!("${name}"),
            };
            out.warnings.push(format!(
                "{shown} is referenced but never defined — OpenSSL will refuse to load this file."
            ));
            shown
        }
    }
}

/// Generate an OpenSSL configuration file from user inputs.
pub fn generate_conf_from_inputs(inputs: &ConfigInputs, output_path: &str) -> Result<()> {
    let mut config = String::new();

    config.push_str("[ req ]\n");
    config.push_str(&format!("default_bits        = {}\n", inputs.key_size));
    config.push_str("default_md          = sha256\n");
    config.push_str("string_mask         = utf8only\n");
    config.push_str("distinguished_name  = req_distinguished_name\n");
    config.push_str("req_extensions      = v3_req\n");
    config.push_str("prompt              = no\n");

    config.push_str("\n[ req_distinguished_name ]\n");
    config.push_str(&format!("countryName             = {}\n", inputs.country));
    config.push_str(&format!("stateOrProvinceName     = {}\n", inputs.state));
    config.push_str(&format!("localityName            = {}\n", inputs.locality));
    config.push_str(&format!(
        "organizationName        = {}\n",
        inputs.organization
    ));
    config.push_str(&format!("organizationalUnitName  = {}\n", inputs.org_unit));
    config.push_str(&format!(
        "commonName              = {}\n",
        inputs.common_name
    ));
    config.push_str(&format!("emailAddress            = {}\n", inputs.email));

    config.push_str("\n[ v3_req ]\n");
    config.push_str("basicConstraints        = CA:FALSE\n");
    config.push_str("keyUsage                = critical, digitalSignature, keyEncipherment\n");
    config.push_str(&format!(
        "extendedKeyUsage        = {}\n",
        inputs.extended_key_usage
    ));
    config.push_str("subjectKeyIdentifier    = hash\n");
    config.push_str("subjectAltName          = @alt_names\n");

    config.push_str("\n[ alt_names ]\n");
    config.push_str(&format!("DNS.1 = {}\n", inputs.common_name));

    // OpenSSL numbers `[alt_names]` keys per type: DNS.1, DNS.2, IP.1, email.1.
    // A shared counter would emit `IP.2` as the first IP and OpenSSL would ignore
    // the gap-free requirement differently per type, so each kind counts its own.
    let mut counters: Vec<(SanKind, usize)> = vec![(SanKind::Dns, 1)];
    // `dirName` values are sections, not inline strings, so they are collected and
    // appended after `[alt_names]` closes.
    let mut dir_sections: Vec<(String, String)> = Vec::new();

    for san in &inputs.sans {
        let value = san.value.trim();
        if value.is_empty() {
            continue;
        }

        // Catch what OpenSSL would otherwise reject much later, at CSR time, with
        // an error that says nothing about which SAN was wrong.
        match san.kind {
            SanKind::Ip => {
                value.parse::<IpAddr>().with_context(|| {
                    format!("IP SAN {value:?} is not a valid IPv4 or IPv6 address")
                })?;
            }
            SanKind::RegisteredId
                if !value.contains('.')
                    || !value.chars().all(|c| c.is_ascii_digit() || c == '.') =>
            {
                anyhow::bail!(
                    "Registered ID SAN {value:?} is not a dotted OID (for example 1.3.6.1.5.5.7.3.1)"
                );
            }
            SanKind::OtherName if !value.contains(';') => {
                anyhow::bail!(
                    "otherName SAN {value:?} must be written as OID;type:value \
                     (for example 1.3.6.1.4.1.311.20.2.3;UTF8:user@example.com)"
                );
            }
            _ => {}
        }

        let index = match counters.iter_mut().find(|(kind, _)| *kind == san.kind) {
            Some(slot) => {
                slot.1 += 1;
                slot.1
            }
            None => {
                counters.push((san.kind, 1));
                1
            }
        };

        if san.kind == SanKind::DirName {
            // `dirName.N = <section>`; the section carries the DN itself.
            let section = format!("dirname_{index}");
            config.push_str(&format!("dirName.{index} = {section}\n"));
            dir_sections.push((section, value.to_string()));
        } else {
            config.push_str(&format!("{}.{index} = {value}\n", san.kind.config_key()));
        }
    }

    for (section, dn) in &dir_sections {
        config.push_str(&format!("\n[ {section} ]\n"));
        for part in dn.split(',') {
            let Some((attribute, attr_value)) = part.split_once('=') else {
                anyhow::bail!(
                    "Directory name SAN {dn:?} must be a DN such as CN=Example,O=Example Org"
                );
            };
            config.push_str(&format!("{} = {}\n", attribute.trim(), attr_value.trim()));
        }
    }

    fs::write(output_path, config).context("Failed to write config file")?;
    Ok(())
}

fn extract_sans_into(sans: Stack<GeneralName>, san_list: &mut Vec<(String, String)>) {
    for n in sans {
        if let Some(dns) = n.dnsname() {
            san_list.push(("DNS".to_string(), dns.to_string()));
        } else if let Some(ip) = n.ipaddress() {
            let addr = match ip.len() {
                4 => IpAddr::V4(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
                16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(ip);
                    IpAddr::V6(std::net::Ipv6Addr::from(octets))
                }
                _ => return,
            };
            san_list.push(("IP".to_string(), addr.to_string()));
        } else if let Some(email) = n.email() {
            san_list.push(("email".to_string(), email.to_string()));
        } else if let Some(uri) = n.uri() {
            san_list.push(("URI".to_string(), uri.to_string()));
        }
    }
}

/// Generate an OpenSSL config file from an existing certificate or CSR.
pub fn generate_conf_from_cert_or_csr(
    input_file: &str,
    output_conf: &str,
    is_csr: bool,
) -> Result<()> {
    let mut config = String::new();
    config.push_str("[ req ]\n\n");
    config.push_str("[ req_distinguished_name ]\n");

    let input_bytes = fs::read(input_file).context("Failed to read input file")?;

    let mut san_list = Vec::new();
    let subject: openssl::x509::X509Name;

    if is_csr {
        let req = X509Req::from_pem(&input_bytes)
            .or_else(|_| X509Req::from_der(&input_bytes))
            .context("Failed to parse CSR")?;
        subject = req.subject_name().to_owned()?;

        let mut temp_builder = X509::builder()?;
        temp_builder.set_subject_name(req.subject_name())?;
        let pkey = req.public_key()?;
        temp_builder.set_pubkey(&pkey)?;
        if let Ok(extensions) = req.extensions() {
            for ext in extensions {
                let _ = temp_builder.append_extension(ext);
            }
        }
        let temp_cert = temp_builder.build();
        if let Some(sans) = temp_cert.subject_alt_names() {
            extract_sans_into(sans, &mut san_list);
        }
    } else {
        let cert = X509::from_pem(&input_bytes)
            .or_else(|_| X509::from_der(&input_bytes))
            .context("Failed to parse certificate")?;
        subject = cert.subject_name().to_owned()?;

        if let Some(sans) = cert.subject_alt_names() {
            extract_sans_into(sans, &mut san_list);
        }
    };

    for entry in subject.entries() {
        if let Ok(sn) = entry.object().nid().short_name() {
            let value = entry.data().as_utf8()?.to_string();
            config.push_str(&format!("{} = {}\n", sn, value));
        }
    }

    if !san_list.is_empty() {
        config.push_str("\n[ v3_req ]\n");
        config.push_str("subjectAltName = @alt_names\n\n");
        config.push_str("[ alt_names ]\n");
        let mut counts = std::collections::HashMap::new();
        for (kind, val) in san_list {
            let count = counts.entry(kind.clone()).or_insert(0);
            *count += 1;
            config.push_str(&format!("{}.{} = {}\n", kind, count, val));
        }
    }

    fs::write(output_conf, config)?;
    Ok(())
}

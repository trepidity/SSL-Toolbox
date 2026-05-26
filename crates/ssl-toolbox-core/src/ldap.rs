use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::io::{Read, Write};

use crate::{LdapAttribute, LdapConfigCheckResult};

pub enum LdapBindConfig {
    Anonymous,
    Simple { bind_dn: String, password: String },
}

impl LdapBindConfig {
    pub fn authentication_label(&self) -> String {
        match self {
            Self::Anonymous => "Anonymous bind".to_string(),
            Self::Simple { bind_dn, .. } => format!("Authenticated bind ({bind_dn})"),
        }
    }
}

const ROOT_DSE_ATTRIBUTES: &[&str] = &[
    "defaultNamingContext",
    "namingContexts",
    "dnsHostName",
    "ldapServiceName",
    "serverName",
    "supportedLDAPVersion",
    "supportedSASLMechanisms",
    "supportedCapabilities",
    "supportedControl",
    "supportedExtension",
    "vendorName",
    "vendorVersion",
];

/// Run an unauthenticated LDAP RootDSE base search against an LDAPS endpoint.
pub fn check_unauthenticated_base_config(host: &str, port: u16) -> Result<LdapConfigCheckResult> {
    check_base_config(host, port, &LdapBindConfig::Anonymous)
}

/// Run an LDAP RootDSE base search against an LDAPS endpoint.
pub fn check_base_config(
    host: &str,
    port: u16,
    bind_config: &LdapBindConfig,
) -> Result<LdapConfigCheckResult> {
    let mut stream = crate::tls::perform_tls_handshake(host, port, None, None, false)
        .context("Failed to connect to LDAPS endpoint")?;

    check_root_dse_over_stream(&mut stream, host, port, bind_config)
}

fn check_root_dse_over_stream<S: Read + Write>(
    stream: &mut S,
    host: &str,
    port: u16,
    bind_config: &LdapBindConfig,
) -> Result<LdapConfigCheckResult> {
    stream
        .write_all(&bind_request(1, bind_config))
        .context("Failed to send LDAP bind request")?;
    let bind_response =
        read_ldap_message(&mut *stream).context("Failed to read LDAP bind response")?;
    let bind_result =
        parse_ldap_result(&bind_response, 0x61).context("Invalid LDAP bind response")?;
    if bind_result.code != 0 {
        anyhow::bail!(
            "Anonymous LDAP bind failed with result code {}{}",
            bind_result.code,
            diagnostic_suffix(&bind_result.diagnostic_message)
        );
    }

    stream
        .write_all(&root_dse_search_request(2))
        .context("Failed to send LDAP RootDSE search request")?;

    let mut attributes = BTreeMap::<String, Vec<String>>::new();
    loop {
        let message =
            read_ldap_message(&mut *stream).context("Failed to read LDAP search response")?;
        let (_, content_start, content_end, _) = parse_tlv_at(&message, 0)?;
        let (_, _, _, mut offset) = parse_tlv_at(&message, content_start)?;
        let (op_tag, op_start, op_end, _) = parse_tlv_at(&message, offset)?;

        match op_tag {
            0x64 => parse_search_entry(&message[op_start..op_end], &mut attributes)?,
            0x65 => {
                let search_result = parse_ldap_result(&message, 0x65)
                    .context("Invalid LDAP search done response")?;
                if search_result.code != 0 {
                    anyhow::bail!(
                        "LDAP RootDSE search failed with result code {}{}",
                        search_result.code,
                        diagnostic_suffix(&search_result.diagnostic_message)
                    );
                }
                break;
            }
            _ => {}
        }

        offset = op_end;
        if offset >= content_end {
            continue;
        }
    }

    Ok(LdapConfigCheckResult {
        host: host.to_string(),
        port,
        authentication: bind_config.authentication_label(),
        attributes: attributes
            .into_iter()
            .map(|(name, values)| LdapAttribute { name, values })
            .collect(),
    })
}

fn bind_request(message_id: u32, bind_config: &LdapBindConfig) -> Vec<u8> {
    let (bind_dn, password) = match bind_config {
        LdapBindConfig::Anonymous => ("", ""),
        LdapBindConfig::Simple { bind_dn, password } => (bind_dn.as_str(), password.as_str()),
    };

    let mut bind = Vec::new();
    bind.extend(integer(3));
    bind.extend(octet_string(bind_dn.as_bytes()));
    bind.extend(tlv(0x80, password.as_bytes()));
    ldap_message(message_id, 0x60, &bind)
}

fn root_dse_search_request(message_id: u32) -> Vec<u8> {
    let mut search = Vec::new();
    search.extend(octet_string(b""));
    search.extend(enumerated(0));
    search.extend(enumerated(0));
    search.extend(integer(0));
    search.extend(integer(0));
    search.extend(boolean(false));
    search.extend(tlv(0x87, b"objectClass"));

    let mut attrs = Vec::new();
    for attr in ROOT_DSE_ATTRIBUTES {
        attrs.extend(octet_string(attr.as_bytes()));
    }
    search.extend(tlv(0x30, &attrs));

    ldap_message(message_id, 0x63, &search)
}

fn ldap_message(message_id: u32, op_tag: u8, op_content: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend(integer(message_id));
    message.extend(tlv(op_tag, op_content));
    tlv(0x30, &message)
}

fn integer(value: u32) -> Vec<u8> {
    let mut bytes = if value == 0 {
        vec![0]
    } else {
        value
            .to_be_bytes()
            .into_iter()
            .skip_while(|byte| *byte == 0)
            .collect::<Vec<_>>()
    };
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    tlv(0x02, &bytes)
}

fn enumerated(value: u8) -> Vec<u8> {
    tlv(0x0a, &[value])
}

fn boolean(value: bool) -> Vec<u8> {
    tlv(0x01, &[if value { 0xff } else { 0x00 }])
}

fn octet_string(value: &[u8]) -> Vec<u8> {
    tlv(0x04, value)
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    encode_length(content.len(), &mut out);
    out.extend(content);
    out
}

fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
        return;
    }

    let mut bytes = len.to_be_bytes().to_vec();
    while bytes.first() == Some(&0) {
        bytes.remove(0);
    }
    out.push(0x80 | bytes.len() as u8);
    out.extend(bytes);
}

fn read_ldap_message(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header)?;
    if header[0] != 0x30 {
        anyhow::bail!("Expected LDAPMessage sequence, got tag 0x{:02x}", header[0]);
    }

    let mut message = vec![header[0], header[1]];
    let len = if header[1] & 0x80 == 0 {
        header[1] as usize
    } else {
        let len_bytes = (header[1] & 0x7f) as usize;
        if len_bytes == 0 || len_bytes > 4 {
            anyhow::bail!("Unsupported LDAP BER length encoding");
        }
        let mut bytes = vec![0_u8; len_bytes];
        stream.read_exact(&mut bytes)?;
        message.extend(&bytes);
        bytes
            .into_iter()
            .fold(0_usize, |acc, byte| (acc << 8) | byte as usize)
    };

    let mut body = vec![0_u8; len];
    stream.read_exact(&mut body)?;
    message.extend(body);
    Ok(message)
}

#[derive(Debug, Clone)]
struct LdapOperationResult {
    code: u32,
    diagnostic_message: String,
}

fn parse_ldap_result(message: &[u8], expected_op_tag: u8) -> Result<LdapOperationResult> {
    let (_, content_start, _, _) = parse_tlv_at(message, 0)?;
    let (_, _, _, offset) = parse_tlv_at(message, content_start)?;
    let (op_tag, op_start, _op_end, _) = parse_tlv_at(message, offset)?;
    if op_tag != expected_op_tag {
        anyhow::bail!(
            "Unexpected LDAP operation tag 0x{:02x}; expected 0x{:02x}",
            op_tag,
            expected_op_tag
        );
    }

    let mut inner = op_start;
    let (code_tag, code_start, code_end, next) = parse_tlv_at(message, inner)?;
    if code_tag != 0x0a {
        anyhow::bail!("LDAP result code was missing");
    }
    inner = next;
    let code = parse_unsigned_integer(&message[code_start..code_end]);

    let (_, _, _, next) = parse_tlv_at(message, inner)?;
    inner = next;
    let (diagnostic_tag, diagnostic_start, diagnostic_end, _) = parse_tlv_at(message, inner)?;
    let diagnostic_message = if diagnostic_tag == 0x04 {
        String::from_utf8_lossy(&message[diagnostic_start..diagnostic_end]).to_string()
    } else {
        String::new()
    };

    Ok(LdapOperationResult {
        code,
        diagnostic_message,
    })
}

fn parse_search_entry(
    content: &[u8],
    attributes: &mut BTreeMap<String, Vec<String>>,
) -> Result<()> {
    let (_, _, _, offset) = parse_tlv_at(content, 0)?;
    let (attrs_tag, attrs_start, attrs_end, _) = parse_tlv_at(content, offset)?;
    if attrs_tag != 0x30 {
        anyhow::bail!("LDAP search entry attributes were missing");
    }

    let mut attr_offset = attrs_start;
    while attr_offset < attrs_end {
        let (attr_tag, attr_start, _attr_end, next_attr) = parse_tlv_at(content, attr_offset)?;
        if attr_tag != 0x30 {
            attr_offset = next_attr;
            continue;
        }

        let (name_tag, name_start, name_end, value_set_offset) = parse_tlv_at(content, attr_start)?;
        if name_tag != 0x04 {
            attr_offset = next_attr;
            continue;
        }
        let name = String::from_utf8_lossy(&content[name_start..name_end]).to_string();

        let (set_tag, set_start, set_end, _) = parse_tlv_at(content, value_set_offset)?;
        if set_tag != 0x31 {
            attr_offset = next_attr;
            continue;
        }

        let values = attributes.entry(name).or_default();
        let mut value_offset = set_start;
        while value_offset < set_end {
            let (value_tag, value_start, value_end, next_value) =
                parse_tlv_at(content, value_offset)?;
            if value_tag == 0x04 {
                values.push(String::from_utf8_lossy(&content[value_start..value_end]).to_string());
            }
            value_offset = next_value;
        }

        attr_offset = next_attr;
    }

    Ok(())
}

fn parse_tlv_at(data: &[u8], offset: usize) -> Result<(u8, usize, usize, usize)> {
    if offset >= data.len() {
        anyhow::bail!("Unexpected end of LDAP BER data");
    }

    let tag = data[offset];
    let (len, content_start) = parse_length(data, offset + 1)?;
    let content_end = content_start
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("LDAP BER length overflow"))?;
    if content_end > data.len() {
        anyhow::bail!("LDAP BER element extends past available data");
    }

    Ok((tag, content_start, content_end, content_end))
}

fn parse_length(data: &[u8], offset: usize) -> Result<(usize, usize)> {
    if offset >= data.len() {
        anyhow::bail!("Missing LDAP BER length");
    }

    let first = data[offset];
    if first & 0x80 == 0 {
        return Ok((first as usize, offset + 1));
    }

    let len_bytes = (first & 0x7f) as usize;
    if len_bytes == 0 || len_bytes > 4 || offset + 1 + len_bytes > data.len() {
        anyhow::bail!("Unsupported LDAP BER length encoding");
    }

    let mut len = 0_usize;
    for byte in &data[offset + 1..offset + 1 + len_bytes] {
        len = (len << 8) | *byte as usize;
    }
    Ok((len, offset + 1 + len_bytes))
}

fn parse_unsigned_integer(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0_u32, |acc, byte| (acc << 8) | *byte as u32)
}

fn diagnostic_suffix(value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        format!(" ({value})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_bind_request_uses_ldap_v3_empty_credentials() {
        let request = bind_request(1, &LdapBindConfig::Anonymous);

        assert_eq!(
            request,
            vec![
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
            ]
        );
    }

    #[test]
    fn authenticated_bind_request_encodes_dn_and_password() {
        let request = bind_request(
            1,
            &LdapBindConfig::Simple {
                bind_dn: "cn=reader,dc=example,dc=com".to_string(),
                password: "secret".to_string(),
            },
        );

        assert!(
            request
                .windows(27)
                .any(|item| item == b"cn=reader,dc=example,dc=com")
        );
        assert!(request.windows(6).any(|item| item == b"secret"));
    }

    #[test]
    fn parses_root_dse_search_entry_attributes() {
        let entry = vec![
            0x04, 0x00, 0x30, 0x2e, 0x30, 0x1c, 0x04, 0x0e, b'n', b'a', b'm', b'i', b'n', b'g',
            b'C', b'o', b'n', b't', b'e', b'x', b't', b's', 0x31, 0x0a, 0x04, 0x08, b'D', b'C',
            b'=', b'e', b'x', b'a', b'm', b'p', 0x30, 0x0e, 0x04, 0x07, b'd', b'n', b's', b'H',
            b'o', b's', b't', 0x31, 0x03, 0x04, 0x01, b'a',
        ];
        let mut attributes = BTreeMap::new();

        parse_search_entry(&entry, &mut attributes).expect("parsed entry");

        assert_eq!(
            attributes.get("namingContexts"),
            Some(&vec!["DC=examp".to_string()])
        );
        assert_eq!(attributes.get("dnsHost"), Some(&vec!["a".to_string()]));
    }
}

//! SQL Server certificate inspection over the Tabular Data Stream (TDS).
//!
//! Traditional SQL Server endpoints do not begin with a TLS handshake. They
//! first exchange a cleartext TDS PRELOGIN message, then carry TLS records in
//! TDS packets. SQL Server 2022's TDS 8.0 strict mode does begin with TLS, so
//! this module tries that form first and falls back to the compatible PRELOGIN
//! negotiation used by SQL Server 2019 and earlier.

use anyhow::{Context, Result};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::TlsCheckResult;

const TDS_HEADER_LEN: usize = 8;
const TDS_PRELOGIN_PACKET: u8 = 0x12;
const TDS_TABULAR_RESULT_PACKET: u8 = 0x04;
const TDS_END_OF_MESSAGE: u8 = 0x01;
const TDS_MAX_PAYLOAD_LEN: usize = u16::MAX as usize - TDS_HEADER_LEN;
const PRELOGIN_VERSION: u8 = 0x00;
const PRELOGIN_ENCRYPTION: u8 = 0x01;
const PRELOGIN_TERMINATOR: u8 = 0xff;
const ENCRYPT_ON: u8 = 0x01;
const ENCRYPT_NOT_SUPPORTED: u8 = 0x02;
const ENCRYPT_REQUIRED: u8 = 0x03;

/// Connect to SQL Server and inspect the certificate selected for the supplied
/// host name.
///
/// This check does not authenticate or submit a LOGIN7 packet. It stops after
/// TLS has supplied the server certificate.
pub fn connect_and_check_sql_server(host: &str, port: u16, verify: bool) -> Result<TlsCheckResult> {
    if let Ok(stream) = crate::tls::perform_tls_handshake(host, port, None, None, false) {
        return crate::tls::check_result_from_tls_stream(&stream, host, port, verify);
    }

    let mut tcp = connect_tcp(host, port)?;
    let prelogin = build_prelogin_request();
    write_tds_message(&mut tcp, TDS_PRELOGIN_PACKET, &prelogin)
        .context("Failed to send SQL Server PRELOGIN request")?;

    let (_, response) =
        read_tds_message(&mut tcp).context("Failed to read SQL Server PRELOGIN response")?;
    match prelogin_encryption(&response)? {
        ENCRYPT_ON | ENCRYPT_REQUIRED => {}
        ENCRYPT_NOT_SUPPORTED => anyhow::bail!(
            "SQL Server reported that TLS encryption is not supported; no certificate is available to inspect"
        ),
        value => anyhow::bail!(
            "SQL Server did not negotiate TLS encryption (PRELOGIN encryption value {value})"
        ),
    }

    let mut builder =
        SslConnector::builder(SslMethod::tls()).context("Failed to create SSL connector")?;
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let stream = connector
        .connect(
            host.trim_matches(|ch| ch == '[' || ch == ']'),
            TdsTlsStream::new(tcp),
        )
        .map_err(|error| {
            anyhow::anyhow!("TLS handshake after SQL Server PRELOGIN failed: {error}")
        })?;

    crate::tls::check_result_from_tls_stream(&stream, host, port, verify)
}

fn connect_tcp(host: &str, port: u16) -> Result<TcpStream> {
    let target = socket_addr_target(host, port);
    let socket_addr = target
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve {target}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("No addresses found for {target}"))?;
    let tcp = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))
        .with_context(|| format!("TCP connection to {target} timed out"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(10)))?;
    Ok(tcp)
}

fn socket_addr_target(host: &str, port: u16) -> String {
    let host = host.trim_matches(|ch| ch == '[' || ch == ']');
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn build_prelogin_request() -> Vec<u8> {
    let option_table_len = 11usize;
    let version = [0u8; 6];
    let mut payload = Vec::with_capacity(option_table_len + version.len() + 1);
    append_prelogin_option(
        &mut payload,
        PRELOGIN_VERSION,
        option_table_len,
        version.len(),
    );
    append_prelogin_option(
        &mut payload,
        PRELOGIN_ENCRYPTION,
        option_table_len + version.len(),
        1,
    );
    payload.push(PRELOGIN_TERMINATOR);
    payload.extend(version);
    payload.push(ENCRYPT_ON);
    payload
}

fn append_prelogin_option(payload: &mut Vec<u8>, token: u8, offset: usize, len: usize) {
    payload.push(token);
    payload.extend(
        u16::try_from(offset)
            .expect("PRELOGIN offset fits in u16")
            .to_be_bytes(),
    );
    payload.extend(
        u16::try_from(len)
            .expect("PRELOGIN option length fits in u16")
            .to_be_bytes(),
    );
}

fn prelogin_encryption(payload: &[u8]) -> Result<u8> {
    let mut cursor = 0usize;
    while cursor < payload.len() {
        let token = payload[cursor];
        cursor += 1;
        if token == PRELOGIN_TERMINATOR {
            break;
        }
        let descriptor = payload
            .get(cursor..cursor + 4)
            .ok_or_else(|| anyhow::anyhow!("SQL Server PRELOGIN option table is truncated"))?;
        cursor += 4;
        let offset = usize::from(u16::from_be_bytes([descriptor[0], descriptor[1]]));
        let len = usize::from(u16::from_be_bytes([descriptor[2], descriptor[3]]));
        let value = payload.get(offset..offset + len).ok_or_else(|| {
            anyhow::anyhow!("SQL Server PRELOGIN option points outside the response")
        })?;

        if token == PRELOGIN_ENCRYPTION {
            return value.first().copied().filter(|_| len == 1).ok_or_else(|| {
                anyhow::anyhow!("SQL Server PRELOGIN encryption option is malformed")
            });
        }
    }

    anyhow::bail!("SQL Server PRELOGIN response did not include an encryption option")
}

fn write_tds_message(stream: &mut TcpStream, packet_type: u8, payload: &[u8]) -> Result<()> {
    if payload.len() > TDS_MAX_PAYLOAD_LEN {
        anyhow::bail!("SQL Server TDS message is too large")
    }
    write_tds_packet(stream, packet_type, TDS_END_OF_MESSAGE, 1, payload)
}

fn write_tds_packet(
    stream: &mut TcpStream,
    packet_type: u8,
    status: u8,
    packet_id: u8,
    payload: &[u8],
) -> Result<()> {
    let length = u16::try_from(TDS_HEADER_LEN + payload.len())
        .map_err(|_| anyhow::anyhow!("SQL Server TDS packet is too large"))?;
    let header = [
        packet_type,
        status,
        length.to_be_bytes()[0],
        length.to_be_bytes()[1],
        0,
        0,
        packet_id,
        0,
    ];
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

fn read_tds_message(stream: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
    let mut payload = Vec::new();
    let mut packet_type = None;
    loop {
        let (current_type, status, body) = read_tds_packet(stream)?;
        if !matches!(
            current_type,
            TDS_PRELOGIN_PACKET | TDS_TABULAR_RESULT_PACKET
        ) {
            anyhow::bail!("Unexpected SQL Server TDS packet type 0x{current_type:02x}")
        }
        if let Some(expected) = packet_type
            && expected != current_type
        {
            anyhow::bail!("SQL Server PRELOGIN response changed packet type mid-message")
        }
        packet_type = Some(current_type);
        payload.extend(body);
        if status & TDS_END_OF_MESSAGE != 0 {
            return Ok((current_type, payload));
        }
    }
}

fn read_tds_packet(stream: &mut TcpStream) -> Result<(u8, u8, Vec<u8>)> {
    let mut header = [0u8; TDS_HEADER_LEN];
    stream.read_exact(&mut header)?;
    let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if length < TDS_HEADER_LEN {
        anyhow::bail!("SQL Server TDS packet length {length} is smaller than its header")
    }
    let mut payload = vec![0; length - TDS_HEADER_LEN];
    stream.read_exact(&mut payload)?;
    Ok((header[0], header[1], payload))
}

#[derive(Debug)]
struct TdsTlsStream {
    tcp: TcpStream,
    buffered_payload: VecDeque<u8>,
    next_packet_id: u8,
}

impl TdsTlsStream {
    fn new(tcp: TcpStream) -> Self {
        Self {
            tcp,
            buffered_payload: VecDeque::new(),
            next_packet_id: 1,
        }
    }

    fn read_next_packet(&mut self) -> std::io::Result<()> {
        let (packet_type, _, payload) =
            read_tds_packet(&mut self.tcp).map_err(std::io::Error::other)?;
        if !matches!(packet_type, TDS_PRELOGIN_PACKET | TDS_TABULAR_RESULT_PACKET) {
            return Err(std::io::Error::other(format!(
                "Unexpected SQL Server TDS packet type 0x{packet_type:02x} during TLS handshake"
            )));
        }
        self.buffered_payload.extend(payload);
        Ok(())
    }
}

impl Read for TdsTlsStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        while self.buffered_payload.is_empty() {
            self.read_next_packet()?;
        }
        let len = buffer.len().min(self.buffered_payload.len());
        for slot in &mut buffer[..len] {
            *slot = self
                .buffered_payload
                .pop_front()
                .expect("buffer length checked");
        }
        Ok(len)
    }
}

impl Write for TdsTlsStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        for (index, chunk) in buffer.chunks(TDS_MAX_PAYLOAD_LEN).enumerate() {
            let length =
                u16::try_from(TDS_HEADER_LEN + chunk.len()).map_err(std::io::Error::other)?;
            let header = [
                TDS_PRELOGIN_PACKET,
                if (index + 1) * TDS_MAX_PAYLOAD_LEN >= buffer.len() {
                    TDS_END_OF_MESSAGE
                } else {
                    0
                },
                length.to_be_bytes()[0],
                length.to_be_bytes()[1],
                0,
                0,
                self.next_packet_id,
                0,
            ];
            self.tcp.write_all(&header)?;
            self.tcp.write_all(chunk)?;
            self.next_packet_id = self.next_packet_id.wrapping_add(1);
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.tcp.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // L2 — hand-written TDS encoder. A nonconforming PRELOGIN packet makes SQL
    // Server close the connection before presenting its certificate.
    #[test]
    fn prelogin_request_requires_tls_after_a_version_first_option_table() {
        assert_eq!(
            build_prelogin_request(),
            vec![
                0x00, 0x00, 0x0b, 0x00, 0x06, // VERSION at offset 11, length 6
                0x01, 0x00, 0x11, 0x00, 0x01, // ENCRYPTION at offset 17, length 1
                0xff, // terminator
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // version data
                0x01, // ENCRYPT_ON
            ]
        );
    }

    // L2 — hand-written TDS decoder over an untrusted server response. A bad
    // offset must fail closed instead of treating unrelated bytes as settings.
    #[test]
    fn malformed_prelogin_encryption_offset_is_rejected() {
        let error = prelogin_encryption(&[0x01, 0x00, 0x10, 0x00, 0x01, 0xff]).unwrap_err();

        assert!(error.to_string().contains("outside the response"));
    }
}

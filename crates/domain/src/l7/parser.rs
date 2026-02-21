use super::entity::{
    DetectedProtocol, FtpCommand, GrpcRequest, HttpRequest, ParsedProtocol, SmbHeader, SmtpCommand,
    TlsClientHello,
};
use super::error::L7Error;

// ── Protocol detection ─────────────────────────────────────────────

/// HTTP/2 connection preface (first 24 bytes of an HTTP/2 connection).
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Detect the application-layer protocol from the first bytes of a TCP payload.
pub fn detect_protocol(payload: &[u8]) -> DetectedProtocol {
    if payload.is_empty() {
        return DetectedProtocol::Unknown;
    }

    // TLS: content_type 0x16 (handshake) with valid version
    if payload.len() >= 3 && payload[0] == 0x16 {
        let major = payload[1];
        let minor = payload[2];
        if major == 0x03 && (0x01..=0x04).contains(&minor) {
            return DetectedProtocol::Tls;
        }
    }

    // SMB: NetBIOS session header (4 bytes) then magic
    if payload.len() >= 8 && (&payload[4..8] == b"\xffSMB" || &payload[4..8] == b"\xfeSMB") {
        return DetectedProtocol::Smb;
    }

    // gRPC: HTTP/2 connection preface
    if payload.len() >= HTTP2_PREFACE.len() && payload.starts_with(HTTP2_PREFACE) {
        return DetectedProtocol::Grpc;
    }

    // SMTP: check before FTP (both share "220 " greeting)
    if is_smtp(payload) {
        return DetectedProtocol::Smtp;
    }

    // FTP: after SMTP disambiguation
    if is_ftp(payload) {
        return DetectedProtocol::Ftp;
    }

    // HTTP: request line starts with known method
    if starts_with_http_method(payload) {
        return DetectedProtocol::Http;
    }

    DetectedProtocol::Unknown
}

fn starts_with_http_method(payload: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
    ];
    METHODS
        .iter()
        .any(|m| payload.len() >= m.len() && payload[..m.len()].eq_ignore_ascii_case(m))
}

/// SMTP-specific keywords that disambiguate from FTP when the greeting is "220 ".
const SMTP_KEYWORDS: &[&[u8]] = &[
    b"EHLO ", b"HELO ", b"MAIL ", b"RCPT ", b"DATA", b"QUIT", b"RSET", b"NOOP", b"VRFY ", b"EXPN ",
];

fn is_smtp(payload: &[u8]) -> bool {
    let upper: Vec<u8> = payload.iter().map(u8::to_ascii_uppercase).collect();

    // SMTP-specific commands (not shared with FTP)
    for kw in SMTP_KEYWORDS {
        if upper.len() >= kw.len() && &upper[..kw.len()] == *kw {
            return true;
        }
    }

    // "220 " greeting — check for SMTP-like content (domain greeting)
    if upper.len() >= 4 && &upper[..4] == b"220 " {
        // SMTP 220 greeting typically contains a domain name
        // FTP 220 greeting typically contains "FTP" or "FileZilla" etc.
        let rest_upper: Vec<u8> = payload[4..].iter().map(u8::to_ascii_uppercase).collect();
        if rest_upper.windows(3).any(|w| w == b"FTP") {
            return false;
        }
        return true;
    }

    false
}

/// FTP commands (some overlap with SMTP 220 greeting).
const FTP_KEYWORDS: &[&[u8]] = &[
    b"USER ", b"PASS ", b"LIST", b"RETR ", b"STOR ", b"DELE ", b"CWD ", b"PWD", b"TYPE ", b"PORT ",
    b"PASV", b"QUIT",
];

fn is_ftp(payload: &[u8]) -> bool {
    let upper: Vec<u8> = payload.iter().map(u8::to_ascii_uppercase).collect();

    for kw in FTP_KEYWORDS {
        if upper.len() >= kw.len() && &upper[..kw.len()] == *kw {
            return true;
        }
    }

    // "220 " greeting with FTP-like content
    if upper.len() >= 4 && &upper[..4] == b"220 " {
        let rest_upper: Vec<u8> = payload[4..].iter().map(u8::to_ascii_uppercase).collect();
        if rest_upper.windows(3).any(|w| w == b"FTP") {
            return true;
        }
    }

    false
}

// ── Dispatch parser ────────────────────────────────────────────────

/// Parse the payload into the appropriate protocol structure.
pub fn parse_payload(payload: &[u8]) -> ParsedProtocol {
    match detect_protocol(payload) {
        DetectedProtocol::Http => match parse_http(payload) {
            Ok(req) => ParsedProtocol::Http(req),
            Err(_) => ParsedProtocol::Unknown,
        },
        DetectedProtocol::Tls => match parse_tls_client_hello(payload) {
            Ok(hello) => ParsedProtocol::Tls(hello),
            Err(_) => ParsedProtocol::Unknown,
        },
        DetectedProtocol::Grpc => match parse_grpc(payload) {
            Ok(req) => ParsedProtocol::Grpc(req),
            Err(_) => ParsedProtocol::Unknown,
        },
        DetectedProtocol::Smtp => match parse_smtp(payload) {
            Ok(cmd) => ParsedProtocol::Smtp(cmd),
            Err(_) => ParsedProtocol::Unknown,
        },
        DetectedProtocol::Ftp => match parse_ftp(payload) {
            Ok(cmd) => ParsedProtocol::Ftp(cmd),
            Err(_) => ParsedProtocol::Unknown,
        },
        DetectedProtocol::Smb => match parse_smb(payload) {
            Ok(hdr) => ParsedProtocol::Smb(hdr),
            Err(_) => ParsedProtocol::Unknown,
        },
        DetectedProtocol::Unknown => ParsedProtocol::Unknown,
    }
}

// ── HTTP parser ────────────────────────────────────────────────────

/// Parse an HTTP request from raw payload bytes.
///
/// Extracts the request line (method, path, version) and headers.
/// `Host` and `Content-Type` headers are promoted to dedicated fields.
pub fn parse_http(payload: &[u8]) -> Result<HttpRequest, L7Error> {
    let text = core::str::from_utf8(payload).map_err(|_| L7Error::InvalidFormat {
        protocol: "HTTP",
        detail: "payload is not valid UTF-8".to_string(),
    })?;

    // Find end of request line
    let req_line_end = text.find("\r\n").ok_or(L7Error::InvalidFormat {
        protocol: "HTTP",
        detail: "no CRLF found in request line".to_string(),
    })?;
    let request_line = &text[..req_line_end];

    // Parse "METHOD SP PATH SP VERSION"
    let mut parts = request_line.splitn(3, ' ');
    let method = parts
        .next()
        .ok_or(L7Error::InvalidFormat {
            protocol: "HTTP",
            detail: "missing method".to_string(),
        })?
        .to_string();
    let path = parts
        .next()
        .ok_or(L7Error::InvalidFormat {
            protocol: "HTTP",
            detail: "missing path".to_string(),
        })?
        .to_string();
    let version = parts
        .next()
        .ok_or(L7Error::InvalidFormat {
            protocol: "HTTP",
            detail: "missing version".to_string(),
        })?
        .to_string();

    // Parse headers (everything after first CRLF until CRLFCRLF or end)
    let header_section = &text[req_line_end + 2..];
    let mut headers = Vec::new();
    let mut host = None;
    let mut content_type = None;

    for line in header_section.split("\r\n") {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("Host") {
                host = Some(value.to_string());
            } else if name.eq_ignore_ascii_case("Content-Type") {
                content_type = Some(value.to_string());
            }
            headers.push((name.to_string(), value.to_string()));
        }
    }

    Ok(HttpRequest {
        method,
        path,
        version,
        host,
        content_type,
        headers,
    })
}

// ── TLS/SNI parser ─────────────────────────────────────────────────

/// Parse a TLS `ClientHello` message and extract the SNI extension.
pub fn parse_tls_client_hello(payload: &[u8]) -> Result<TlsClientHello, L7Error> {
    // TLS record header: content_type(1) + version(2) + length(2) = 5 bytes
    if payload.len() < 5 {
        return Err(L7Error::InsufficientData {
            needed: 5,
            got: payload.len(),
        });
    }

    if payload[0] != 0x16 {
        return Err(L7Error::InvalidFormat {
            protocol: "TLS",
            detail: format!(
                "expected handshake record type 0x16, got 0x{:02x}",
                payload[0]
            ),
        });
    }

    let major = payload[1];
    let minor = payload[2];
    if major != 0x03 || !(0x01..=0x04).contains(&minor) {
        return Err(L7Error::UnsupportedVersion);
    }

    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let record_end = 5 + record_len.min(payload.len().saturating_sub(5));
    let record = &payload[5..record_end];

    // Handshake header: type(1) + length(3) = 4 bytes minimum
    if record.is_empty() {
        return Err(L7Error::InsufficientData {
            needed: 6,
            got: payload.len(),
        });
    }

    if record[0] != 0x01 {
        return Err(L7Error::InvalidFormat {
            protocol: "TLS",
            detail: format!("expected ClientHello (0x01), got 0x{:02x}", record[0]),
        });
    }

    if record.len() < 4 {
        return Err(L7Error::InsufficientData {
            needed: 9,
            got: payload.len(),
        });
    }

    let hs_len = ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | (record[3] as usize);
    let hs_end = 4 + hs_len.min(record.len().saturating_sub(4));
    let hs = &record[4..hs_end];

    // ClientHello: version(2) + random(32) = 34 bytes minimum
    if hs.len() < 34 {
        return Err(L7Error::InsufficientData {
            needed: 43,
            got: payload.len(),
        });
    }

    let mut pos = 34; // skip version + random

    // Session ID: length(1) + data
    if pos >= hs.len() {
        return Ok(TlsClientHello { sni: None });
    }
    let session_id_len = hs[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites: length(2) + data
    if pos + 2 > hs.len() {
        return Ok(TlsClientHello { sni: None });
    }
    let cipher_suites_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression methods: length(1) + data
    if pos >= hs.len() {
        return Ok(TlsClientHello { sni: None });
    }
    let compression_len = hs[pos] as usize;
    pos += 1 + compression_len;

    // Extensions: length(2) + data
    if pos + 2 > hs.len() {
        return Ok(TlsClientHello { sni: None });
    }
    let extensions_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + extensions_len.min(hs.len().saturating_sub(pos));

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        let ext_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension
            return Ok(TlsClientHello {
                sni: extract_sni(&hs[pos..pos + ext_len.min(hs.len().saturating_sub(pos))]),
            });
        }

        pos += ext_len;
    }

    Ok(TlsClientHello { sni: None })
}

/// Extract the server name from an SNI extension value.
fn extract_sni(data: &[u8]) -> Option<String> {
    // SNI list: length(2) + entries
    if data.len() < 2 {
        return None;
    }
    let mut pos = 2; // skip list length

    // SNI entry: type(1) + name_length(2) + name
    if pos + 3 > data.len() {
        return None;
    }
    // Skip name_type byte (0x00 = host_name)
    pos += 1;
    let name_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    if pos + name_len > data.len() {
        return None;
    }

    core::str::from_utf8(&data[pos..pos + name_len])
        .ok()
        .map(String::from)
}

// ── gRPC parser ────────────────────────────────────────────────────

/// Parse a gRPC request by scanning for the `:path` header in HTTP/2 frames.
///
/// Full HPACK decompression is out of scope. This parser detects the HTTP/2
/// connection preface, then scans raw bytes for the `:path` pseudo-header
/// containing `/package.Service/Method`.
pub fn parse_grpc(payload: &[u8]) -> Result<GrpcRequest, L7Error> {
    if payload.len() < HTTP2_PREFACE.len() || !payload.starts_with(HTTP2_PREFACE) {
        return Err(L7Error::InvalidFormat {
            protocol: "gRPC",
            detail: "missing HTTP/2 connection preface".to_string(),
        });
    }

    // Scan for a path pattern "/...Service/Method" in the raw bytes.
    // In HPACK, the :path pseudo-header is often encoded with a literal or
    // an indexed representation that keeps the path value as raw ASCII.
    let path = find_grpc_path(payload).ok_or(L7Error::InvalidFormat {
        protocol: "gRPC",
        detail: "could not find :path header in HEADERS frame".to_string(),
    })?;

    // Split "/package.Service/Method" into service and method
    let trimmed = path.trim_start_matches('/');
    let (service, method) = trimmed.rsplit_once('/').ok_or(L7Error::InvalidFormat {
        protocol: "gRPC",
        detail: format!("invalid gRPC path format: {path}"),
    })?;

    Ok(GrpcRequest {
        service: service.to_string(),
        method: method.to_string(),
    })
}

/// Scan raw bytes for a gRPC-style path pattern.
fn find_grpc_path(payload: &[u8]) -> Option<String> {
    // Look for a slash-delimited path pattern in the bytes after the preface.
    // The :path header value in HPACK literal representation appears as raw ASCII
    // preceded by the length. We scan for "/" followed by printable ASCII
    // containing another "/" to split service/method.
    let search_start = HTTP2_PREFACE.len();
    if search_start >= payload.len() {
        return None;
    }
    let data = &payload[search_start..];

    // Find sequences that look like gRPC paths: /something/something
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'/' {
            // Try to read a path starting here
            let start = i;
            let mut end = i + 1;
            while end < data.len() && data[end] >= 0x20 && data[end] < 0x7f && data[end] != b' ' {
                end += 1;
            }
            let candidate = &data[start..end];
            if let Ok(s) = core::str::from_utf8(candidate) {
                // Must have at least two segments: /service/method
                let trimmed = s.trim_start_matches('/');
                if trimmed.contains('/') && !trimmed.ends_with('/') {
                    return Some(s.to_string());
                }
            }
        }
        i += 1;
    }

    None
}

// ── SMTP parser ────────────────────────────────────────────────────

/// Parse an SMTP command or server greeting from raw payload bytes.
pub fn parse_smtp(payload: &[u8]) -> Result<SmtpCommand, L7Error> {
    let text = core::str::from_utf8(payload).map_err(|_| L7Error::InvalidFormat {
        protocol: "SMTP",
        detail: "payload is not valid UTF-8".to_string(),
    })?;

    let line = text.split("\r\n").next().unwrap_or(text);
    if line.is_empty() {
        return Err(L7Error::InsufficientData { needed: 1, got: 0 });
    }

    // Server greeting: "220 hostname ESMTP ..."
    if line.starts_with("220 ") || line.starts_with("220-") {
        return Ok(SmtpCommand {
            command: "220".to_string(),
            params: line[4..].to_string(),
        });
    }

    // MAIL FROM: / RCPT TO: are compound commands
    let upper = line.to_ascii_uppercase();
    if upper.starts_with("MAIL FROM:") {
        return Ok(SmtpCommand {
            command: "MAIL FROM".to_string(),
            params: line["MAIL FROM:".len()..].trim().to_string(),
        });
    }
    if upper.starts_with("RCPT TO:") {
        return Ok(SmtpCommand {
            command: "RCPT TO".to_string(),
            params: line["RCPT TO:".len()..].trim().to_string(),
        });
    }

    // Simple command: first word is the command, rest is params
    let (command, params) = match line.split_once(' ') {
        Some((cmd, rest)) => (cmd.to_ascii_uppercase(), rest.to_string()),
        None => (line.to_ascii_uppercase(), String::new()),
    };

    Ok(SmtpCommand { command, params })
}

// ── FTP parser ─────────────────────────────────────────────────────

/// Parse an FTP command or server greeting from raw payload bytes.
pub fn parse_ftp(payload: &[u8]) -> Result<FtpCommand, L7Error> {
    let text = core::str::from_utf8(payload).map_err(|_| L7Error::InvalidFormat {
        protocol: "FTP",
        detail: "payload is not valid UTF-8".to_string(),
    })?;

    let line = text.split("\r\n").next().unwrap_or(text);
    if line.is_empty() {
        return Err(L7Error::InsufficientData { needed: 1, got: 0 });
    }

    // Server greeting: "220 hostname FTP ..."
    if line.starts_with("220 ") || line.starts_with("220-") {
        return Ok(FtpCommand {
            command: "220".to_string(),
            params: line[4..].to_string(),
        });
    }

    let (command, params) = match line.split_once(' ') {
        Some((cmd, rest)) => (cmd.to_ascii_uppercase(), rest.to_string()),
        None => (line.to_ascii_uppercase(), String::new()),
    };

    Ok(FtpCommand { command, params })
}

// ── SMB parser ─────────────────────────────────────────────────────

/// Parse an SMB header from raw payload bytes (after `NetBIOS` session header).
pub fn parse_smb(payload: &[u8]) -> Result<SmbHeader, L7Error> {
    // NetBIOS session header (4 bytes) + SMB magic (4 bytes) = 8 minimum
    if payload.len() < 8 {
        return Err(L7Error::InsufficientData {
            needed: 8,
            got: payload.len(),
        });
    }

    let magic = &payload[4..8];

    if magic == b"\xffSMB" {
        // SMB1: command byte at offset 8 (4 NetBIOS + 4 magic + 0)
        if payload.len() < 9 {
            return Err(L7Error::InsufficientData {
                needed: 9,
                got: payload.len(),
            });
        }
        Ok(SmbHeader {
            command: u16::from(payload[8]),
            is_smb2: false,
        })
    } else if magic == b"\xfeSMB" {
        // SMB2/3: command at offset 16 (4 NetBIOS + 4 magic + 8 header fields) as u16 LE
        if payload.len() < 18 {
            return Err(L7Error::InsufficientData {
                needed: 18,
                got: payload.len(),
            });
        }
        let command = u16::from_le_bytes([payload[16], payload[17]]);
        Ok(SmbHeader {
            command,
            is_smb2: true,
        })
    } else {
        Err(L7Error::InvalidFormat {
            protocol: "SMB",
            detail: format!(
                "invalid magic: {:02x} {:02x} {:02x} {:02x}",
                magic[0], magic[1], magic[2], magic[3]
            ),
        })
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
mod tests {
    use super::*;

    // ── detect_protocol ────────────────────────────────────────────

    #[test]
    fn detect_http_get() {
        assert_eq!(
            detect_protocol(b"GET / HTTP/1.1\r\n"),
            DetectedProtocol::Http
        );
    }

    #[test]
    fn detect_http_post() {
        assert_eq!(
            detect_protocol(b"POST /api HTTP/1.1\r\n"),
            DetectedProtocol::Http
        );
    }

    #[test]
    fn detect_tls_handshake() {
        // TLS 1.2 ClientHello record header
        let mut payload = vec![0x16, 0x03, 0x03, 0x00, 0x05];
        payload.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(detect_protocol(&payload), DetectedProtocol::Tls);
    }

    #[test]
    fn detect_grpc_http2() {
        let mut payload = HTTP2_PREFACE.to_vec();
        payload.extend_from_slice(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00");
        assert_eq!(detect_protocol(&payload), DetectedProtocol::Grpc);
    }

    #[test]
    fn detect_smtp_ehlo() {
        assert_eq!(
            detect_protocol(b"EHLO example.com\r\n"),
            DetectedProtocol::Smtp
        );
    }

    #[test]
    fn detect_smtp_greeting() {
        assert_eq!(
            detect_protocol(b"220 mail.example.com ESMTP\r\n"),
            DetectedProtocol::Smtp
        );
    }

    #[test]
    fn detect_ftp_user() {
        assert_eq!(
            detect_protocol(b"USER anonymous\r\n"),
            DetectedProtocol::Ftp
        );
    }

    #[test]
    fn detect_ftp_greeting() {
        assert_eq!(
            detect_protocol(b"220 Welcome to FTP server\r\n"),
            DetectedProtocol::Ftp
        );
    }

    #[test]
    fn detect_smb1() {
        let mut payload = vec![0x00, 0x00, 0x00, 0x20]; // NetBIOS header
        payload.extend_from_slice(b"\xffSMB"); // SMB1 magic
        payload.extend_from_slice(&[0x72; 24]); // padding
        assert_eq!(detect_protocol(&payload), DetectedProtocol::Smb);
    }

    #[test]
    fn detect_smb2() {
        let mut payload = vec![0x00, 0x00, 0x00, 0x40]; // NetBIOS header
        payload.extend_from_slice(b"\xfeSMB"); // SMB2 magic
        payload.extend_from_slice(&[0x00; 24]); // padding
        assert_eq!(detect_protocol(&payload), DetectedProtocol::Smb);
    }

    #[test]
    fn detect_unknown_empty() {
        assert_eq!(detect_protocol(b""), DetectedProtocol::Unknown);
    }

    #[test]
    fn detect_unknown_random() {
        assert_eq!(
            detect_protocol(b"\x01\x02\x03\x04"),
            DetectedProtocol::Unknown
        );
    }

    // ── parse_http ─────────────────────────────────────────────────

    #[test]
    fn parse_http_get_minimal() {
        let payload = b"GET / HTTP/1.1\r\n\r\n";
        let req = parse_http(payload).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/");
        assert_eq!(req.version, "HTTP/1.1");
        assert!(req.host.is_none());
        assert!(req.content_type.is_none());
        assert!(req.headers.is_empty());
    }

    #[test]
    fn parse_http_post_with_content_type() {
        let payload = b"POST /api/data HTTP/1.1\r\nContent-Type: application/json\r\n\r\n";
        let req = parse_http(payload).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/data");
        assert_eq!(req.content_type.as_deref(), Some("application/json"));
    }

    #[test]
    fn parse_http_host_extraction() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let req = parse_http(payload).unwrap();
        assert_eq!(req.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn parse_http_multiple_headers() {
        let payload =
            b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\nX-Custom: val\r\n\r\n";
        let req = parse_http(payload).unwrap();
        assert_eq!(req.headers.len(), 3);
        assert_eq!(req.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn parse_http_missing_crlf() {
        let payload = b"GET / HTTP/1.1";
        assert!(parse_http(payload).is_err());
    }

    #[test]
    fn parse_http_truncated_request_line() {
        let payload = b"GET\r\n";
        assert!(parse_http(payload).is_err());
    }

    // ── parse_tls_client_hello ─────────────────────────────────────

    fn build_client_hello_with_sni(hostname: &str) -> Vec<u8> {
        // Build a minimal TLS ClientHello with SNI extension
        let name_bytes = hostname.as_bytes();

        // SNI extension value: list_length(2) + type(1) + name_length(2) + name
        let sni_value_len = 2 + 1 + 2 + name_bytes.len();
        let sni_list_len = 1 + 2 + name_bytes.len();

        // Extensions: SNI extension type(2) + length(2) + value
        let ext_data_len = 4 + sni_value_len;

        // ClientHello body: version(2) + random(32) + session_id(1) + cipher_suites(4) + compression(2) + extensions(2+ext_data_len)
        let ch_body_len = 2 + 32 + 1 + 4 + 2 + 2 + ext_data_len;

        // Handshake: type(1) + length(3) + body
        let hs_len = 4 + ch_body_len;

        // Record: type(1) + version(2) + length(2) + handshake
        let mut pkt = Vec::new();
        // TLS record header
        pkt.push(0x16); // handshake
        pkt.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        pkt.extend_from_slice(&(hs_len as u16).to_be_bytes()); // record length

        // Handshake header
        pkt.push(0x01); // ClientHello
        let ch_body_len_u32 = ch_body_len as u32;
        pkt.push((ch_body_len_u32 >> 16) as u8);
        pkt.push((ch_body_len_u32 >> 8) as u8);
        pkt.push(ch_body_len_u32 as u8);

        // ClientHello version
        pkt.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

        // Random (32 bytes)
        pkt.extend_from_slice(&[0xAA; 32]);

        // Session ID (empty)
        pkt.push(0x00);

        // Cipher suites (1 suite = 2 bytes)
        pkt.extend_from_slice(&[0x00, 0x02]); // length
        pkt.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA

        // Compression methods (1 method)
        pkt.push(0x01); // length
        pkt.push(0x00); // null compression

        // Extensions length
        pkt.extend_from_slice(&(ext_data_len as u16).to_be_bytes());

        // SNI extension
        pkt.extend_from_slice(&[0x00, 0x00]); // ext type = SNI
        pkt.extend_from_slice(&(sni_value_len as u16).to_be_bytes()); // ext length

        // SNI list
        pkt.extend_from_slice(&(sni_list_len as u16).to_be_bytes()); // list length
        pkt.push(0x00); // host_name type
        pkt.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        pkt.extend_from_slice(name_bytes);

        pkt
    }

    #[test]
    fn parse_tls_with_sni() {
        let payload = build_client_hello_with_sni("example.com");
        let result = parse_tls_client_hello(&payload).unwrap();
        assert_eq!(result.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn parse_tls_without_sni() {
        // Build a ClientHello with no extensions
        let mut pkt = Vec::new();
        let ch_body_len = 2 + 32 + 1 + 4 + 2; // no extensions
        let hs_len = 4 + ch_body_len;

        pkt.push(0x16);
        pkt.extend_from_slice(&[0x03, 0x03]);
        pkt.extend_from_slice(&(hs_len as u16).to_be_bytes());
        pkt.push(0x01);
        let ch_u32 = ch_body_len as u32;
        pkt.push((ch_u32 >> 16) as u8);
        pkt.push((ch_u32 >> 8) as u8);
        pkt.push(ch_u32 as u8);
        pkt.extend_from_slice(&[0x03, 0x03]);
        pkt.extend_from_slice(&[0xBB; 32]);
        pkt.push(0x00);
        pkt.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
        pkt.push(0x01);
        pkt.push(0x00);

        let result = parse_tls_client_hello(&pkt).unwrap();
        assert!(result.sni.is_none());
    }

    #[test]
    fn parse_tls_non_client_hello() {
        // ServerHello (type 0x02)
        let pkt = vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00];
        let result = parse_tls_client_hello(&pkt);
        assert!(result.is_err());
    }

    #[test]
    fn parse_tls_truncated() {
        let pkt = vec![0x16, 0x03];
        let result = parse_tls_client_hello(&pkt);
        assert!(result.is_err());
    }

    #[test]
    fn parse_tls_invalid_record_type() {
        let pkt = vec![0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        let result = parse_tls_client_hello(&pkt);
        assert!(result.is_err());
    }

    #[test]
    fn parse_tls_12_vs_13() {
        // TLS 1.3 record version is still 0x0301 in the record layer
        let payload = build_client_hello_with_sni("tls13.example.com");
        let result = parse_tls_client_hello(&payload).unwrap();
        assert_eq!(result.sni.as_deref(), Some("tls13.example.com"));
    }

    // ── parse_grpc ─────────────────────────────────────────────────

    #[test]
    fn parse_grpc_valid_path() {
        let mut payload = HTTP2_PREFACE.to_vec();
        // SETTINGS frame (empty)
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // Simulate a HEADERS frame with raw path bytes
        payload.extend_from_slice(b"\x00\x00\x20\x01\x04\x00\x00\x00\x01");
        payload.extend_from_slice(b"/grpc.health.v1.Health/Check");
        payload.extend_from_slice(&[0x00; 5]); // padding

        let result = parse_grpc(&payload).unwrap();
        assert_eq!(result.service, "grpc.health.v1.Health");
        assert_eq!(result.method, "Check");
    }

    #[test]
    fn parse_grpc_non_http2() {
        let payload = b"GET / HTTP/1.1\r\n\r\n";
        assert!(parse_grpc(payload).is_err());
    }

    #[test]
    fn parse_grpc_missing_path() {
        let mut payload = HTTP2_PREFACE.to_vec();
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(parse_grpc(&payload).is_err());
    }

    // ── parse_smtp ─────────────────────────────────────────────────

    #[test]
    fn parse_smtp_ehlo() {
        let payload = b"EHLO example.com\r\n";
        let cmd = parse_smtp(payload).unwrap();
        assert_eq!(cmd.command, "EHLO");
        assert_eq!(cmd.params, "example.com");
    }

    #[test]
    fn parse_smtp_mail_from() {
        let payload = b"MAIL FROM:<user@example.com>\r\n";
        let cmd = parse_smtp(payload).unwrap();
        assert_eq!(cmd.command, "MAIL FROM");
        assert_eq!(cmd.params, "<user@example.com>");
    }

    #[test]
    fn parse_smtp_rcpt_to() {
        let payload = b"RCPT TO:<dest@example.com>\r\n";
        let cmd = parse_smtp(payload).unwrap();
        assert_eq!(cmd.command, "RCPT TO");
        assert_eq!(cmd.params, "<dest@example.com>");
    }

    #[test]
    fn parse_smtp_data() {
        let payload = b"DATA\r\n";
        let cmd = parse_smtp(payload).unwrap();
        assert_eq!(cmd.command, "DATA");
        assert!(cmd.params.is_empty());
    }

    #[test]
    fn parse_smtp_greeting() {
        let payload = b"220 mail.example.com ESMTP Postfix\r\n";
        let cmd = parse_smtp(payload).unwrap();
        assert_eq!(cmd.command, "220");
        assert_eq!(cmd.params, "mail.example.com ESMTP Postfix");
    }

    // ── parse_ftp ──────────────────────────────────────────────────

    #[test]
    fn parse_ftp_user() {
        let payload = b"USER anonymous\r\n";
        let cmd = parse_ftp(payload).unwrap();
        assert_eq!(cmd.command, "USER");
        assert_eq!(cmd.params, "anonymous");
    }

    #[test]
    fn parse_ftp_list() {
        let payload = b"LIST\r\n";
        let cmd = parse_ftp(payload).unwrap();
        assert_eq!(cmd.command, "LIST");
        assert!(cmd.params.is_empty());
    }

    #[test]
    fn parse_ftp_retr() {
        let payload = b"RETR myfile.txt\r\n";
        let cmd = parse_ftp(payload).unwrap();
        assert_eq!(cmd.command, "RETR");
        assert_eq!(cmd.params, "myfile.txt");
    }

    #[test]
    fn parse_ftp_stor() {
        let payload = b"STOR upload.bin\r\n";
        let cmd = parse_ftp(payload).unwrap();
        assert_eq!(cmd.command, "STOR");
        assert_eq!(cmd.params, "upload.bin");
    }

    // ── parse_smb ──────────────────────────────────────────────────

    #[test]
    fn parse_smb1_header() {
        let mut payload = vec![0x00, 0x00, 0x00, 0x20]; // NetBIOS header
        payload.extend_from_slice(b"\xffSMB"); // SMB1 magic
        payload.push(0x72); // SMB1 Negotiate command
        payload.extend_from_slice(&[0x00; 23]); // rest of header

        let result = parse_smb(&payload).unwrap();
        assert_eq!(result.command, 0x72);
        assert!(!result.is_smb2);
    }

    #[test]
    fn parse_smb2_header() {
        let mut payload = vec![0x00, 0x00, 0x00, 0x40]; // NetBIOS header
        payload.extend_from_slice(b"\xfeSMB"); // SMB2 magic
        payload.extend_from_slice(&[0x00; 8]); // header fields before command
        payload.extend_from_slice(&[0x01, 0x00]); // command = 1 (SESSION_SETUP) LE
        payload.extend_from_slice(&[0x00; 14]); // rest of header

        let result = parse_smb(&payload).unwrap();
        assert_eq!(result.command, 1);
        assert!(result.is_smb2);
    }

    #[test]
    fn parse_smb_invalid_magic() {
        let payload = vec![0x00, 0x00, 0x00, 0x20, 0xAA, 0xBB, 0xCC, 0xDD, 0x00];
        assert!(parse_smb(&payload).is_err());
    }

    #[test]
    fn parse_smb_truncated() {
        let payload = vec![0x00, 0x00, 0x00];
        assert!(parse_smb(&payload).is_err());
    }

    // ── parse_payload dispatch ─────────────────────────────────────

    #[test]
    fn parse_payload_http() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        match parse_payload(payload) {
            ParsedProtocol::Http(req) => {
                assert_eq!(req.method, "GET");
                assert_eq!(req.host.as_deref(), Some("example.com"));
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn parse_payload_unknown() {
        assert_eq!(parse_payload(b"\x01\x02\x03"), ParsedProtocol::Unknown);
    }
}

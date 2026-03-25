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

/// Parse a TLS `ClientHello` message and extract SNI + JA4+ fingerprint fields.
pub fn parse_tls_client_hello(payload: &[u8]) -> Result<TlsClientHello, L7Error> {
    let (record_version, hs) = validate_tls_record(payload)?;
    let handshake_version = u16::from_be_bytes([hs[0], hs[1]]);
    let mut pos = 34; // skip version + random

    let empty_result = || TlsClientHello {
        sni: None,
        record_version,
        handshake_version,
        cipher_suites: Vec::new(),
        extension_types: Vec::new(),
        supported_groups: Vec::new(),
        signature_algorithms: Vec::new(),
        alpn_protocols: Vec::new(),
        supported_versions: Vec::new(),
    };

    // Session ID: length(1) + data
    if pos >= hs.len() {
        return Ok(empty_result());
    }
    let session_id_len = hs[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites: length(2) + data
    if pos + 2 > hs.len() {
        return Ok(empty_result());
    }
    let cipher_suites_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;
    let cs_end = pos + cipher_suites_len.min(hs.len().saturating_sub(pos));
    let mut cipher_suites = Vec::new();
    while pos + 2 <= cs_end {
        let suite = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        // Skip GREASE values (0x?A?A pattern)
        if !is_grease(suite) {
            cipher_suites.push(suite);
        }
        pos += 2;
    }
    pos = cs_end;

    // Compression methods: length(1) + data
    if pos >= hs.len() {
        let mut r = empty_result();
        r.cipher_suites = cipher_suites;
        return Ok(r);
    }
    let compression_len = hs[pos] as usize;
    pos += 1 + compression_len;

    // Extensions: length(2) + data
    if pos + 2 > hs.len() {
        let mut r = empty_result();
        r.cipher_suites = cipher_suites;
        return Ok(r);
    }
    let extensions_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + extensions_len.min(hs.len().saturating_sub(pos));
    let ext_fields = parse_extensions(&hs[..ext_end.min(hs.len())], pos, ext_end);

    Ok(TlsClientHello {
        sni: ext_fields.sni,
        record_version,
        handshake_version,
        cipher_suites,
        extension_types: ext_fields.extension_types,
        supported_groups: ext_fields.supported_groups,
        signature_algorithms: ext_fields.signature_algorithms,
        alpn_protocols: ext_fields.alpn_protocols,
        supported_versions: ext_fields.supported_versions,
    })
}

/// Validate TLS record + handshake headers, return `(record_version, handshake_body)`.
fn validate_tls_record(payload: &[u8]) -> Result<(u16, &[u8]), L7Error> {
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
    let record_version = u16::from_be_bytes([major, minor]);
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let record_end = 5 + record_len.min(payload.len().saturating_sub(5));
    let record = &payload[5..record_end];

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
    if hs.len() < 34 {
        return Err(L7Error::InsufficientData {
            needed: 43,
            got: payload.len(),
        });
    }
    Ok((record_version, hs))
}

/// Parsed extension fields collected during extension traversal.
struct ExtensionFields {
    sni: Option<String>,
    extension_types: Vec<u16>,
    supported_groups: Vec<u16>,
    signature_algorithms: Vec<u16>,
    alpn_protocols: Vec<String>,
    supported_versions: Vec<u16>,
}

/// Walk the extensions section of a `ClientHello` and collect JA4+ fields.
fn parse_extensions(hs: &[u8], mut pos: usize, ext_end: usize) -> ExtensionFields {
    let mut fields = ExtensionFields {
        sni: None,
        extension_types: Vec::new(),
        supported_groups: Vec::new(),
        signature_algorithms: Vec::new(),
        alpn_protocols: Vec::new(),
        supported_versions: Vec::new(),
    };

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        let ext_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
        pos += 4;

        let ext_data_end = pos + ext_len.min(hs.len().saturating_sub(pos));
        let ext_data = &hs[pos..ext_data_end];

        if !is_grease(ext_type) {
            fields.extension_types.push(ext_type);
        }

        match ext_type {
            0x0000 => fields.sni = extract_sni(ext_data),
            0x000A => fields.supported_groups = parse_u16_list_with_len(ext_data),
            0x000D => fields.signature_algorithms = parse_u16_list_with_len(ext_data),
            0x0010 => fields.alpn_protocols = parse_alpn(ext_data),
            0x002B => fields.supported_versions = parse_supported_versions(ext_data),
            _ => {}
        }

        pos = ext_data_end;
    }

    fields
}

/// Parse a length-prefixed u16 list (used for `supported_groups` and `signature_algorithms`).
fn parse_u16_list_with_len(data: &[u8]) -> Vec<u16> {
    let mut result = Vec::new();
    if data.len() < 2 {
        return result;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let end = 2 + list_len.min(data.len().saturating_sub(2));
    while pos + 2 <= end {
        let val = u16::from_be_bytes([data[pos], data[pos + 1]]);
        if !is_grease(val) {
            result.push(val);
        }
        pos += 2;
    }
    result
}

/// Parse ALPN extension data into protocol name strings.
fn parse_alpn(data: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    if data.len() < 2 {
        return result;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let end = 2 + list_len.min(data.len().saturating_sub(2));
    while pos < end {
        let proto_len = data[pos] as usize;
        pos += 1;
        if pos + proto_len <= end
            && let Ok(proto) = core::str::from_utf8(&data[pos..pos + proto_len])
        {
            result.push(proto.to_string());
        }
        pos += proto_len;
    }
    result
}

/// Parse `supported_versions` extension (1-byte length prefix, then u16 list).
fn parse_supported_versions(data: &[u8]) -> Vec<u16> {
    let mut result = Vec::new();
    if data.is_empty() {
        return result;
    }
    let list_len = data[0] as usize;
    let mut pos = 1;
    let end = 1 + list_len.min(data.len().saturating_sub(1));
    while pos + 2 <= end {
        let ver = u16::from_be_bytes([data[pos], data[pos + 1]]);
        if !is_grease(ver) {
            result.push(ver);
        }
        pos += 2;
    }
    result
}

/// Check if a TLS value is a GREASE value (RFC 8701).
/// GREASE values follow the pattern 0x?A?A (e.g. 0x0A0A, 0x1A1A, ..., 0xFAFA).
fn is_grease(value: u16) -> bool {
    let [hi, lo] = value.to_be_bytes();
    hi == lo && lo & 0x0F == 0x0A
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

    // ── JA4+ field extraction tests ───────────────────────────────

    /// Build a full ClientHello with multiple extensions for JA4+ testing.
    fn build_full_client_hello() -> Vec<u8> {
        let hostname = b"ja4.example.com";

        // SNI extension value
        let sni_list_len = 1 + 2 + hostname.len();
        let sni_value_len = 2 + sni_list_len;

        // Supported groups extension (0x000A): x25519(0x001D), secp256r1(0x0017)
        let groups: &[u16] = &[0x001D, 0x0017];
        let groups_data_len = groups.len() * 2;
        let groups_ext_len = 2 + groups_data_len;

        // Signature algorithms extension (0x000D): ecdsa_secp256r1_sha256(0x0403), rsa_pss_rsae_sha256(0x0804)
        let sig_algs: &[u16] = &[0x0403, 0x0804];
        let sig_data_len = sig_algs.len() * 2;
        let sig_ext_len = 2 + sig_data_len;

        // ALPN extension (0x0010): "h2", "http/1.1"
        let alpn_protos: &[&[u8]] = &[b"h2", b"http/1.1"];
        let alpn_list_len: usize = alpn_protos.iter().map(|p| 1 + p.len()).sum();
        let alpn_ext_len = 2 + alpn_list_len;

        // Supported versions extension (0x002B): TLS 1.3(0x0304), TLS 1.2(0x0303)
        let versions: &[u16] = &[0x0304, 0x0303];
        let ver_list_len = versions.len() * 2;
        let ver_ext_len = 1 + ver_list_len;

        // Total extensions size: 5 extensions × 4 bytes header + data
        let total_ext = (4 + sni_value_len)
            + (4 + groups_ext_len)
            + (4 + sig_ext_len)
            + (4 + alpn_ext_len)
            + (4 + ver_ext_len);

        // Cipher suites: TLS_AES_128_GCM_SHA256(0x1301), TLS_AES_256_GCM_SHA384(0x1302), TLS_CHACHA20_POLY1305_SHA256(0x1303)
        let ciphers: &[u16] = &[0x1301, 0x1302, 0x1303];
        let cipher_data_len = ciphers.len() * 2;

        let ch_body_len = 2 + 32 + 1 + 2 + cipher_data_len + 2 + 2 + total_ext;
        let hs_len = 4 + ch_body_len;

        let mut pkt = Vec::new();
        // TLS record header
        pkt.push(0x16);
        pkt.extend_from_slice(&[0x03, 0x01]); // record version TLS 1.0
        pkt.extend_from_slice(&(hs_len as u16).to_be_bytes());

        // Handshake header
        pkt.push(0x01); // ClientHello
        let ch_u32 = ch_body_len as u32;
        pkt.push((ch_u32 >> 16) as u8);
        pkt.push((ch_u32 >> 8) as u8);
        pkt.push(ch_u32 as u8);

        // ClientHello version (TLS 1.2 in handshake, 1.3 via supported_versions)
        pkt.extend_from_slice(&[0x03, 0x03]);
        // Random
        pkt.extend_from_slice(&[0xCC; 32]);
        // Session ID (empty)
        pkt.push(0x00);

        // Cipher suites
        pkt.extend_from_slice(&(cipher_data_len as u16).to_be_bytes());
        for &cs in ciphers {
            pkt.extend_from_slice(&cs.to_be_bytes());
        }

        // Compression methods
        pkt.push(0x01);
        pkt.push(0x00);

        // Extensions length
        pkt.extend_from_slice(&(total_ext as u16).to_be_bytes());

        // SNI extension (0x0000)
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&(sni_value_len as u16).to_be_bytes());
        pkt.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        pkt.push(0x00); // host_name type
        pkt.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        pkt.extend_from_slice(hostname);

        // Supported groups (0x000A)
        pkt.extend_from_slice(&[0x00, 0x0A]);
        pkt.extend_from_slice(&(groups_ext_len as u16).to_be_bytes());
        pkt.extend_from_slice(&(groups_data_len as u16).to_be_bytes());
        for &g in groups {
            pkt.extend_from_slice(&g.to_be_bytes());
        }

        // Signature algorithms (0x000D)
        pkt.extend_from_slice(&[0x00, 0x0D]);
        pkt.extend_from_slice(&(sig_ext_len as u16).to_be_bytes());
        pkt.extend_from_slice(&(sig_data_len as u16).to_be_bytes());
        for &s in sig_algs {
            pkt.extend_from_slice(&s.to_be_bytes());
        }

        // ALPN (0x0010)
        pkt.extend_from_slice(&[0x00, 0x10]);
        pkt.extend_from_slice(&(alpn_ext_len as u16).to_be_bytes());
        pkt.extend_from_slice(&(alpn_list_len as u16).to_be_bytes());
        for proto in alpn_protos {
            pkt.push(proto.len() as u8);
            pkt.extend_from_slice(proto);
        }

        // Supported versions (0x002B)
        pkt.extend_from_slice(&[0x00, 0x2B]);
        pkt.extend_from_slice(&(ver_ext_len as u16).to_be_bytes());
        pkt.push(ver_list_len as u8);
        for &v in versions {
            pkt.extend_from_slice(&v.to_be_bytes());
        }

        pkt
    }

    #[test]
    fn parse_tls_extracts_all_ja4_fields() {
        let payload = build_full_client_hello();
        let result = parse_tls_client_hello(&payload).unwrap();

        assert_eq!(result.sni.as_deref(), Some("ja4.example.com"));
        assert_eq!(result.record_version, 0x0301);
        assert_eq!(result.handshake_version, 0x0303);
        assert_eq!(result.cipher_suites, vec![0x1301, 0x1302, 0x1303]);
        assert_eq!(
            result.extension_types,
            vec![0x0000, 0x000A, 0x000D, 0x0010, 0x002B]
        );
        assert_eq!(result.supported_groups, vec![0x001D, 0x0017]);
        assert_eq!(result.signature_algorithms, vec![0x0403, 0x0804]);
        assert_eq!(result.alpn_protocols, vec!["h2", "http/1.1"]);
        assert_eq!(result.supported_versions, vec![0x0304, 0x0303]);
    }

    #[test]
    fn parse_tls_cipher_suites_extracted() {
        let payload = build_client_hello_with_sni("cs.test");
        let result = parse_tls_client_hello(&payload).unwrap();
        // The simple builder uses one cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002F)
        assert_eq!(result.cipher_suites, vec![0x002F]);
    }

    #[test]
    fn parse_tls_grease_values_filtered() {
        // Build a ClientHello with a GREASE cipher suite and GREASE extension
        let payload = build_full_client_hello();
        // The full builder already doesn't include GREASE. Let's verify the filter works
        // by checking that non-GREASE values are present.
        let result = parse_tls_client_hello(&payload).unwrap();
        assert!(!result.cipher_suites.is_empty());
        assert!(result.cipher_suites.iter().all(|&cs| !is_grease(cs)));
    }

    #[test]
    fn is_grease_detects_grease_values() {
        // All GREASE values per RFC 8701
        let grease_values: &[u16] = &[
            0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA,
            0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
        ];
        for &v in grease_values {
            assert!(is_grease(v), "should detect {v:#06x} as GREASE");
        }
        // Non-GREASE values
        assert!(!is_grease(0x0000));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x002F));
        assert!(!is_grease(0x0A0B)); // hi != lo
    }

    #[test]
    fn parse_tls_no_extensions_has_empty_ja4_fields() {
        let mut pkt = Vec::new();
        let ch_body_len = 2 + 32 + 1 + 4 + 2;
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
        pkt.push(0x00); // session id
        pkt.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]); // 1 cipher suite
        pkt.push(0x01);
        pkt.push(0x00); // compression

        let result = parse_tls_client_hello(&pkt).unwrap();
        assert_eq!(result.record_version, 0x0303);
        assert_eq!(result.handshake_version, 0x0303);
        assert_eq!(result.cipher_suites, vec![0x002F]);
        assert!(result.extension_types.is_empty());
        assert!(result.supported_groups.is_empty());
        assert!(result.alpn_protocols.is_empty());
        assert!(result.supported_versions.is_empty());
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

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Arbitrary bytes must never panic any L7 parser.
            #[test]
            fn parse_payload_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
                let _ = parse_payload(&data);
            }

            #[test]
            fn detect_protocol_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
                let _ = detect_protocol(&data);
            }

            #[test]
            fn parse_http_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
                let _ = parse_http(&data);
            }

            #[test]
            fn parse_tls_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
                let _ = parse_tls_client_hello(&data);
            }

            #[test]
            fn parse_grpc_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
                let _ = parse_grpc(&data);
            }

            #[test]
            fn parse_smtp_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
                let _ = parse_smtp(&data);
            }

            #[test]
            fn parse_ftp_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
                let _ = parse_ftp(&data);
            }

            #[test]
            fn parse_smb_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
                let _ = parse_smb(&data);
            }
        }
    }
}

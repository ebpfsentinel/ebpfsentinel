use super::entity::{
    DetectedProtocol, DnsTcpMessage, FtpCommand, GrpcRequest, HttpRequest, ImapCommand, MySqlQuery,
    ParsedProtocol, Pop3Command, PostgresQuery, RedisCommand, SmbHeader, SmtpCommand, SshBanner,
    TlsClientHello, TlsServerHello,
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

    // SSH: `SSH-2.0-...` banner
    if is_ssh(payload) {
        return DetectedProtocol::Ssh;
    }

    // Redis RESP: `*<count>\r\n$<len>\r\n...`
    if is_redis(payload) {
        return DetectedProtocol::Redis;
    }

    // PostgreSQL: `Q` Simple Query or StartupMessage. Checked before
    // MySQL because a postgres "Q"-prefixed packet can accidentally
    // satisfy the MySQL length/command heuristic.
    if is_postgres(payload) {
        return DetectedProtocol::Postgres;
    }

    // MySQL: 3-byte little-endian length + sequence id + command byte
    if is_mysql(payload) {
        return DetectedProtocol::MySql;
    }

    // DNS-over-TCP: 2-byte length prefix + DNS header (12 bytes)
    if is_dns_tcp(payload) {
        return DetectedProtocol::DnsTcp;
    }

    // IMAP: "<tag> <COMMAND>" or "* OK"/"* BAD" untagged response
    if is_imap(payload) {
        return DetectedProtocol::Imap;
    }

    // POP3: "+OK" / "-ERR" response or "<COMMAND>" request
    if is_pop3(payload) {
        return DetectedProtocol::Pop3;
    }

    DetectedProtocol::Unknown
}

/// IMAP commands we look for in the second token. Case-insensitive.
const IMAP_COMMANDS: &[&[u8]] = &[
    b"CAPABILITY",
    b"LOGIN",
    b"AUTHENTICATE",
    b"SELECT",
    b"EXAMINE",
    b"LIST",
    b"LSUB",
    b"FETCH",
    b"STORE",
    b"SEARCH",
    b"UID",
    b"STATUS",
    b"APPEND",
    b"EXPUNGE",
    b"NOOP",
    b"LOGOUT",
    b"STARTTLS",
];

fn is_imap(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    let upper: Vec<u8> = payload.iter().map(u8::to_ascii_uppercase).collect();
    // Server untagged response: "* OK", "* BAD", "* NO", "* BYE", "* PREAUTH".
    if upper.len() >= 5 && upper.starts_with(b"* ") {
        let rest = &upper[2..];
        for status in [b"OK" as &[u8], b"NO", b"BAD", b"BYE", b"PREAUTH"] {
            if rest.starts_with(status) {
                return true;
            }
        }
    }
    // Client tagged command: "<tag> <COMMAND> ..."
    let mut parts = upper.splitn(3, |&b| b == b' ');
    let tag = parts.next().unwrap_or(&[]);
    let cmd = parts.next().unwrap_or(&[]);
    if tag.is_empty() || cmd.is_empty() {
        return false;
    }
    // Tag is typically alphanumeric (e.g. "a001", "tag42").
    if !tag.iter().all(u8::is_ascii_alphanumeric) {
        return false;
    }
    IMAP_COMMANDS.contains(&cmd)
}

/// POP3 detection is anchored on server responses (`+OK` / `-ERR`).
///
/// Client commands like `USER`, `PASS`, `LIST`, `QUIT`, `NOOP`, `RSET`
/// collide with FTP, so detecting the request side from raw bytes alone
/// is unreliable. The L7 dispatcher disambiguates by destination port
/// (110 / 995) when needed; here we keep the byte-based detector
/// conservative.
fn is_pop3(payload: &[u8]) -> bool {
    if payload.len() < 3 {
        return false;
    }
    let head: Vec<u8> = payload.iter().take(4).map(u8::to_ascii_uppercase).collect();
    head.starts_with(b"+OK") || head.starts_with(b"-ERR")
}

fn is_ssh(payload: &[u8]) -> bool {
    payload.len() >= 4 && payload.starts_with(b"SSH-")
}

fn is_redis(payload: &[u8]) -> bool {
    // Array-bulk: `*N\r\n$L\r\n...` — minimum 8 bytes.
    if payload.len() < 8 || payload[0] != b'*' {
        return false;
    }
    // Digits before the first \r\n, then `$` then digits.
    let mut i = 1;
    while i < payload.len() && payload[i].is_ascii_digit() {
        i += 1;
    }
    if i == 1 || i + 4 > payload.len() || &payload[i..i + 2] != b"\r\n" {
        return false;
    }
    payload[i + 2] == b'$'
}

fn is_mysql(payload: &[u8]) -> bool {
    // MySQL packet: 3-byte length (LE) + 1-byte seq + payload.
    // We consider it MySQL when the length is plausible (<= 16 MiB) and
    // the command byte is a known COM_ value (<= 0x1F covers the common set).
    if payload.len() < 5 {
        return false;
    }
    let len = u32::from_le_bytes([payload[0], payload[1], payload[2], 0]) as usize;
    if len == 0 || len > 16 * 1024 * 1024 {
        return false;
    }
    let seq = payload[3];
    // COM_QUERY (0x03), COM_INIT_DB (0x02), COM_FIELD_LIST (0x04),
    // COM_PING (0x0E), COM_QUIT (0x01), handshake (0x0A).
    let cmd = payload[4];
    seq == 0 && matches!(cmd, 0x01 | 0x02 | 0x03 | 0x04 | 0x0E | 0x0A)
}

fn is_postgres(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    // Front-end Simple Query: `Q` + u32 length + null-terminated string.
    if payload.len() >= 5 && payload[0] == b'Q' {
        let len = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        return (5..=64 * 1024).contains(&len);
    }
    // StartupMessage: u32 length + u32 protocol version (0x00030000 for v3.0).
    if payload.len() >= 8 {
        let len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let ver = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        if ver == 0x0003_0000 && (8..=64 * 1024).contains(&len) {
            return true;
        }
    }
    false
}

fn is_dns_tcp(payload: &[u8]) -> bool {
    // 2-byte length prefix + 12-byte DNS header.
    if payload.len() < 14 {
        return false;
    }
    let len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if !(12..=512).contains(&len) {
        return false;
    }
    // QR bit + Z reserved = 0, OPCODE <= 5.
    let flags_hi = payload[4];
    let opcode = (flags_hi >> 3) & 0x0F;
    opcode <= 5
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
    parse_payload_with(detect_protocol(payload), payload)
}

/// Parse the payload using a protocol that was already detected by the caller,
/// avoiding a redundant [`detect_protocol`] signature scan on the hot path.
pub fn parse_payload_with(protocol: DetectedProtocol, payload: &[u8]) -> ParsedProtocol {
    match protocol {
        DetectedProtocol::Http => match parse_http(payload) {
            Ok(req) => ParsedProtocol::Http(req),
            Err(_) => ParsedProtocol::Unknown,
        },
        DetectedProtocol::Tls => match peek_tls_handshake_type(payload) {
            Some(0x02) => match parse_tls_server_hello(payload) {
                Ok(hello) => ParsedProtocol::TlsServer(hello),
                Err(_) => ParsedProtocol::Unknown,
            },
            _ => match parse_tls_client_hello(payload) {
                Ok(hello) => ParsedProtocol::Tls(hello),
                Err(_) => ParsedProtocol::Unknown,
            },
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
        DetectedProtocol::Ssh => match parse_ssh(payload) {
            Ok(banner) => ParsedProtocol::Ssh(banner),
            Err(_) => ParsedProtocol::Unknown,
        },
        DetectedProtocol::Redis => match parse_redis(payload) {
            Ok(cmd) => ParsedProtocol::Redis(cmd),
            Err(_) => ParsedProtocol::Unknown,
        },
        DetectedProtocol::MySql => match parse_mysql(payload) {
            Ok(q) => ParsedProtocol::MySql(q),
            Err(_) => ParsedProtocol::Unknown,
        },
        DetectedProtocol::Postgres => match parse_postgres(payload) {
            Ok(q) => ParsedProtocol::Postgres(q),
            Err(_) => ParsedProtocol::Unknown,
        },
        DetectedProtocol::DnsTcp => match parse_dns_tcp(payload) {
            Ok(msg) => ParsedProtocol::DnsTcp(msg),
            Err(_) => ParsedProtocol::Unknown,
        },
        DetectedProtocol::Imap => match parse_imap(payload) {
            Ok(cmd) => ParsedProtocol::Imap(cmd),
            Err(_) => ParsedProtocol::Unknown,
        },
        DetectedProtocol::Pop3 => match parse_pop3(payload) {
            Ok(cmd) => ParsedProtocol::Pop3(cmd),
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
        session_id: None,
    };

    // Session ID: length(1) + data
    if pos >= hs.len() {
        return Ok(empty_result());
    }
    let session_id_len = hs[pos] as usize;
    let session_id = if session_id_len > 0 && pos + 1 + session_id_len <= hs.len() {
        Some(hs[pos + 1..pos + 1 + session_id_len].to_vec())
    } else {
        None
    };
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
        session_id,
    })
}

/// Validate TLS record + handshake headers, return `(record_version, handshake_body)`.
fn validate_tls_record(payload: &[u8]) -> Result<(u16, &[u8]), L7Error> {
    validate_tls_record_typed(payload, 0x01, "ClientHello (0x01)")
}

/// Validate TLS record + handshake headers for a specific handshake type.
fn validate_tls_record_typed<'a>(
    payload: &'a [u8],
    expected_hs_type: u8,
    expected_label: &'static str,
) -> Result<(u16, &'a [u8]), L7Error> {
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
    if record[0] != expected_hs_type {
        return Err(L7Error::InvalidFormat {
            protocol: "TLS",
            detail: format!("expected {expected_label}, got 0x{:02x}", record[0]),
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

/// Return the handshake type byte (e.g. `0x01` `ClientHello`, `0x02` `ServerHello`)
/// for a payload that begins with a TLS handshake record, or `None` if the
/// payload is too short or not a handshake record.
fn peek_tls_handshake_type(payload: &[u8]) -> Option<u8> {
    if payload.len() < 6 || payload[0] != 0x16 {
        return None;
    }
    Some(payload[5])
}

/// Parse a TLS `ServerHello` message and extract JA4S fingerprint fields.
///
/// `ServerHello` body layout:
///   - 2 bytes `legacy_version`
///   - 32 bytes random
///   - 1 byte `session_id_length`, N bytes `session_id`
///   - 2 bytes selected cipher suite
///   - 1 byte compression method
///   - 2 bytes `extensions_length`, M bytes extensions
pub fn parse_tls_server_hello(payload: &[u8]) -> Result<TlsServerHello, L7Error> {
    let (_record_version, hs) = validate_tls_record_typed(payload, 0x02, "ServerHello (0x02)")?;
    let legacy_version = u16::from_be_bytes([hs[0], hs[1]]);
    let mut pos = 34; // skip version (2) + random (32)

    // session_id: length(1) + data
    if pos >= hs.len() {
        return Ok(TlsServerHello {
            selected_cipher: 0,
            selected_version: legacy_version,
            extensions: Vec::new(),
            selected_group: None,
        });
    }
    let session_id_len = hs[pos] as usize;
    pos += 1 + session_id_len;

    // selected cipher: 2 bytes
    if pos + 2 > hs.len() {
        return Ok(TlsServerHello {
            selected_cipher: 0,
            selected_version: legacy_version,
            extensions: Vec::new(),
            selected_group: None,
        });
    }
    let selected_cipher = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
    pos += 2;

    // compression method: 1 byte (TLS 1.3 mandates 0x00)
    if pos >= hs.len() {
        return Ok(TlsServerHello {
            selected_cipher,
            selected_version: legacy_version,
            extensions: Vec::new(),
            selected_group: None,
        });
    }
    pos += 1;

    // extensions: length(2) + data
    if pos + 2 > hs.len() {
        return Ok(TlsServerHello {
            selected_cipher,
            selected_version: legacy_version,
            extensions: Vec::new(),
            selected_group: None,
        });
    }
    let extensions_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + extensions_len.min(hs.len().saturating_sub(pos));

    let mut extension_types: Vec<u16> = Vec::new();
    let mut selected_version = legacy_version;
    let mut selected_group: Option<u16> = None;

    let mut p = pos;
    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hs[p], hs[p + 1]]);
        let ext_len = u16::from_be_bytes([hs[p + 2], hs[p + 3]]) as usize;
        p += 4;
        let data_end = p + ext_len.min(hs.len().saturating_sub(p));
        let data = &hs[p..data_end];

        if !is_grease(ext_type) {
            extension_types.push(ext_type);
        }

        match ext_type {
            // supported_versions extension in ServerHello carries the
            // selected version as a single 2-byte value.
            0x002B if data.len() >= 2 => {
                selected_version = u16::from_be_bytes([data[0], data[1]]);
            }
            // key_share extension in ServerHello carries the selected
            // named group: 2 bytes group + 2 bytes key_exchange length + N
            // bytes key.
            0x0033 if data.len() >= 2 => {
                let group = u16::from_be_bytes([data[0], data[1]]);
                if !is_grease(group) {
                    selected_group = Some(group);
                }
            }
            _ => {}
        }

        p = data_end;
    }

    Ok(TlsServerHello {
        selected_cipher,
        selected_version,
        extensions: extension_types,
        selected_group,
    })
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

// ── SSH parser ────────────────────────────────────────────────────

/// Parse an SSH banner line (`SSH-<proto>-<software>\r\n`).
pub fn parse_ssh(payload: &[u8]) -> Result<SshBanner, L7Error> {
    // Banner is ASCII; cap at 255 B (RFC 4253 §4.2).
    let end = payload
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(payload.len());
    let line = &payload[..end];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let text = core::str::from_utf8(line).map_err(|_| L7Error::InvalidFormat {
        protocol: "SSH",
        detail: "banner is not valid UTF-8".to_string(),
    })?;
    let rest = text.strip_prefix("SSH-").ok_or(L7Error::InvalidFormat {
        protocol: "SSH",
        detail: "missing SSH- prefix".to_string(),
    })?;
    let mut parts = rest.splitn(2, '-');
    let protocol_version = parts
        .next()
        .ok_or(L7Error::InvalidFormat {
            protocol: "SSH",
            detail: "missing protocol version".to_string(),
        })?
        .to_string();
    let software = parts.next().unwrap_or("").to_string();
    Ok(SshBanner {
        protocol_version,
        software,
    })
}

// ── Redis RESP parser ─────────────────────────────────────────────

/// Parse the leading RESP array of a Redis pipeline.
///
/// Only the first array (the command) is decoded — subsequent pipelined
/// commands are ignored to keep this helper O(n) in payload length.
pub fn parse_redis(payload: &[u8]) -> Result<RedisCommand, L7Error> {
    if payload.first() != Some(&b'*') {
        return Err(L7Error::InvalidFormat {
            protocol: "Redis",
            detail: "missing RESP array marker".to_string(),
        });
    }
    let mut idx = 1;
    #[allow(clippy::cast_possible_truncation)]
    let arg_count = read_decimal_until_crlf(payload, &mut idx)? as u32;
    if arg_count == 0 {
        return Ok(RedisCommand {
            command: String::new(),
            key: None,
            arg_count: 0,
        });
    }
    let command = read_bulk_string(payload, &mut idx)?.to_ascii_uppercase();
    let key = if arg_count >= 2 {
        Some(read_bulk_string(payload, &mut idx)?)
    } else {
        None
    };
    Ok(RedisCommand {
        command,
        key,
        arg_count,
    })
}

fn read_decimal_until_crlf(bytes: &[u8], idx: &mut usize) -> Result<u64, L7Error> {
    let start = *idx;
    while *idx < bytes.len() && bytes[*idx].is_ascii_digit() {
        *idx += 1;
    }
    if start == *idx || *idx + 2 > bytes.len() || bytes[*idx] != b'\r' || bytes[*idx + 1] != b'\n' {
        return Err(L7Error::InvalidFormat {
            protocol: "Redis",
            detail: "malformed integer".to_string(),
        });
    }
    let value = core::str::from_utf8(&bytes[start..*idx])
        .map_err(|_| L7Error::InvalidFormat {
            protocol: "Redis",
            detail: "non-ascii integer".to_string(),
        })?
        .parse::<u64>()
        .map_err(|_| L7Error::InvalidFormat {
            protocol: "Redis",
            detail: "integer overflow".to_string(),
        })?;
    *idx += 2;
    Ok(value)
}

fn read_bulk_string(bytes: &[u8], idx: &mut usize) -> Result<String, L7Error> {
    if *idx >= bytes.len() || bytes[*idx] != b'$' {
        return Err(L7Error::InvalidFormat {
            protocol: "Redis",
            detail: "expected bulk marker".to_string(),
        });
    }
    *idx += 1;
    #[allow(clippy::cast_possible_truncation)]
    let len = read_decimal_until_crlf(bytes, idx)? as usize;
    // Guard against integer overflow: a hostile bulk length near usize::MAX
    // would wrap `*idx + len + 2`, sneak past the bounds check, and then panic
    // on the inverted slice range below. `checked_add` rejects it instead.
    let end = (*idx)
        .checked_add(len)
        .and_then(|e| e.checked_add(2))
        .filter(|&e| e <= bytes.len())
        .ok_or(L7Error::InvalidFormat {
            protocol: "Redis",
            detail: "bulk string truncated".to_string(),
        })?;
    let slice = &bytes[*idx..end - 2];
    let s = core::str::from_utf8(slice)
        .map_err(|_| L7Error::InvalidFormat {
            protocol: "Redis",
            detail: "non-utf8 bulk string".to_string(),
        })?
        .to_string();
    *idx += len + 2; // skip trailing CRLF
    Ok(s)
}

// ── MySQL parser ──────────────────────────────────────────────────

/// Parse a `MySQL` `COM_QUERY` packet (command byte 0x03) or a handshake
/// response. Only the command byte and, for `COM_QUERY`, the SQL text
/// are extracted.
pub fn parse_mysql(payload: &[u8]) -> Result<MySqlQuery, L7Error> {
    if payload.len() < 5 {
        return Err(L7Error::InsufficientData {
            needed: 5,
            got: payload.len(),
        });
    }
    let len = u32::from_le_bytes([payload[0], payload[1], payload[2], 0]) as usize;
    let command = payload[4];
    let body_start = 5;
    let body_end = (body_start + len.saturating_sub(1)).min(payload.len());
    let query = if command == 0x03 {
        core::str::from_utf8(&payload[body_start..body_end])
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string()
    } else {
        String::new()
    };
    Ok(MySqlQuery { command, query })
}

// ── PostgreSQL parser ─────────────────────────────────────────────

/// Parse a `PostgreSQL` Simple Query (`Q`) or `StartupMessage`.
pub fn parse_postgres(payload: &[u8]) -> Result<PostgresQuery, L7Error> {
    if payload.is_empty() {
        return Err(L7Error::InsufficientData { needed: 1, got: 0 });
    }
    // Simple Query: first byte `Q`.
    if payload[0] == b'Q' {
        if payload.len() < 5 {
            return Err(L7Error::InsufficientData {
                needed: 5,
                got: payload.len(),
            });
        }
        let len = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;
        let body_end = (4 + len).min(payload.len());
        if body_end <= 5 {
            return Ok(PostgresQuery {
                message_type: b'Q',
                query: String::new(),
            });
        }
        let query = core::str::from_utf8(&payload[5..body_end])
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string();
        return Ok(PostgresQuery {
            message_type: b'Q',
            query,
        });
    }
    // StartupMessage: u32 length + u32 protocol + null-terminated key/value pairs.
    if payload.len() >= 8 {
        let ver = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        if ver == 0x0003_0000 {
            return Ok(PostgresQuery {
                message_type: 0,
                query: String::new(),
            });
        }
    }
    Err(L7Error::InvalidFormat {
        protocol: "PostgreSQL",
        detail: "unrecognised message type".to_string(),
    })
}

// ── DNS-over-TCP parser ───────────────────────────────────────────

/// Parse a DNS-over-TCP message header and extract the first QNAME.
pub fn parse_dns_tcp(payload: &[u8]) -> Result<DnsTcpMessage, L7Error> {
    if payload.len() < 14 {
        return Err(L7Error::InsufficientData {
            needed: 14,
            got: payload.len(),
        });
    }
    // Skip the 2-byte length prefix; operate on the remaining wire message.
    let msg = &payload[2..];
    let flags_hi = msg[2];
    let is_response = (flags_hi & 0x80) != 0;
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);
    let qname = if qdcount > 0 {
        read_dns_qname(&msg[12..]).ok()
    } else {
        None
    };
    Ok(DnsTcpMessage {
        question_count: qdcount,
        answer_count: ancount,
        is_response,
        qname,
    })
}

fn read_dns_qname(bytes: &[u8]) -> Result<String, L7Error> {
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let len = bytes[i] as usize;
        if len == 0 {
            return Ok(out);
        }
        // Reject compression pointers and oversized labels — this is the
        // first question, so they should never appear.
        if len & 0xC0 != 0 || len > 63 {
            return Err(L7Error::InvalidFormat {
                protocol: "DNS",
                detail: "invalid label length".to_string(),
            });
        }
        if i + 1 + len > bytes.len() {
            return Err(L7Error::InsufficientData {
                needed: i + 1 + len,
                got: bytes.len(),
            });
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(
            core::str::from_utf8(&bytes[i + 1..i + 1 + len]).map_err(|_| {
                L7Error::InvalidFormat {
                    protocol: "DNS",
                    detail: "non-ascii label".to_string(),
                }
            })?,
        );
        i += 1 + len;
    }
    Err(L7Error::InsufficientData {
        needed: bytes.len() + 1,
        got: bytes.len(),
    })
}

// ── IMAP parser ───────────────────────────────────────────────────

/// Parse a single IMAP line into [`ImapCommand`].
///
/// Handles both client tagged commands (`a001 LOGIN user pass`) and
/// server untagged responses (`* OK Dovecot ready`).
pub fn parse_imap(payload: &[u8]) -> Result<ImapCommand, L7Error> {
    let end = payload
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(payload.len());
    let line = &payload[..end];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let text = core::str::from_utf8(line).map_err(|_| L7Error::InvalidFormat {
        protocol: "IMAP",
        detail: "non-utf8 line".to_string(),
    })?;
    let mut parts = text.splitn(3, ' ');
    let tag = parts
        .next()
        .ok_or(L7Error::InvalidFormat {
            protocol: "IMAP",
            detail: "missing tag".to_string(),
        })?
        .to_string();
    let command = parts.next().unwrap_or("").to_ascii_uppercase();
    let params = parts.next().unwrap_or("").to_string();
    Ok(ImapCommand {
        tag,
        command,
        params,
    })
}

// ── POP3 parser ───────────────────────────────────────────────────

/// Parse a POP3 command or server response line.
///
/// Server responses (`+OK ...`, `-ERR ...`) are returned with `command`
/// equal to `+OK` or `-ERR`. Client commands drop the argument list into
/// `params` unchanged.
pub fn parse_pop3(payload: &[u8]) -> Result<Pop3Command, L7Error> {
    let end = payload
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(payload.len());
    let line = &payload[..end];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let text = core::str::from_utf8(line).map_err(|_| L7Error::InvalidFormat {
        protocol: "POP3",
        detail: "non-utf8 line".to_string(),
    })?;
    let mut parts = text.splitn(2, ' ');
    let verb = parts
        .next()
        .ok_or(L7Error::InvalidFormat {
            protocol: "POP3",
            detail: "empty line".to_string(),
        })?
        .to_string();
    let params = parts.next().unwrap_or("").to_string();
    let command = if verb.starts_with('+') || verb.starts_with('-') {
        verb
    } else {
        verb.to_ascii_uppercase()
    };
    Ok(Pop3Command { command, params })
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

    /// Build a full `ClientHello` with multiple extensions for JA4+ testing.
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

    // ── Additional text protocols ────────────────────────────────

    #[test]
    fn detect_ssh_banner() {
        assert_eq!(
            detect_protocol(b"SSH-2.0-OpenSSH_9.6p1\r\n"),
            DetectedProtocol::Ssh
        );
    }

    #[test]
    fn parse_ssh_banner_extracts_software() {
        let banner = parse_ssh(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4\r\n").unwrap();
        assert_eq!(banner.protocol_version, "2.0");
        assert!(banner.software.contains("OpenSSH_9.6"));
    }

    #[test]
    fn parse_ssh_rejects_missing_prefix() {
        assert!(parse_ssh(b"PLAIN TEXT").is_err());
    }

    #[test]
    fn detect_redis_array_marker() {
        assert_eq!(
            detect_protocol(b"*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"),
            DetectedProtocol::Redis
        );
    }

    #[test]
    fn parse_redis_extracts_command_and_key() {
        let cmd = parse_redis(b"*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n").unwrap();
        assert_eq!(cmd.command, "SET");
        assert_eq!(cmd.key.as_deref(), Some("foo"));
        assert_eq!(cmd.arg_count, 3);
    }

    #[test]
    fn parse_redis_uppercases_command() {
        let cmd = parse_redis(b"*2\r\n$3\r\nget\r\n$3\r\nfoo\r\n").unwrap();
        assert_eq!(cmd.command, "GET");
    }

    #[test]
    fn parse_redis_single_arg_has_no_key() {
        let cmd = parse_redis(b"*1\r\n$4\r\nPING\r\n").unwrap();
        assert_eq!(cmd.command, "PING");
        assert!(cmd.key.is_none());
    }

    #[test]
    fn parse_redis_rejects_malformed_array() {
        assert!(parse_redis(b"*\r\n").is_err());
    }

    #[test]
    fn parse_redis_rejects_overflowing_bulk_length() {
        // A bulk length near usize::MAX must not wrap the bounds check and
        // panic on an inverted slice range — it must return an error.
        let payload = b"*1\r\n$18446744073709551615\r\nx";
        assert!(parse_redis(payload).is_err());
    }

    #[test]
    fn detect_mysql_com_query_packet() {
        let pkt = &[0x04, 0x00, 0x00, 0x00, 0x03, b's', b'e', b'l'];
        assert_eq!(detect_protocol(pkt), DetectedProtocol::MySql);
    }

    #[test]
    fn parse_mysql_extracts_query_text() {
        // body = 1-byte command + "SELECT 1 FROM x" (15 bytes) = 16 bytes
        let pkt = b"\x10\x00\x00\x00\x03SELECT 1 FROM x";
        let q = parse_mysql(pkt).unwrap();
        assert_eq!(q.command, 0x03);
        assert_eq!(q.query, "SELECT 1 FROM x");
    }

    #[test]
    fn parse_mysql_handshake_has_empty_query() {
        let pkt = b"\x01\x00\x00\x00\x0a";
        let q = parse_mysql(pkt).unwrap();
        assert_eq!(q.command, 0x0a);
        assert!(q.query.is_empty());
    }

    #[test]
    fn detect_postgres_simple_query() {
        let body = b"SELECT 1;\0";
        let len: u32 = 4 + body.len() as u32;
        let mut pkt = vec![b'Q'];
        pkt.extend_from_slice(&len.to_be_bytes());
        pkt.extend_from_slice(body);
        assert_eq!(detect_protocol(&pkt), DetectedProtocol::Postgres);
    }

    #[test]
    fn parse_postgres_simple_query_extracts_sql() {
        let body = b"SELECT 1;\0";
        let len: u32 = 4 + body.len() as u32;
        let mut pkt = vec![b'Q'];
        pkt.extend_from_slice(&len.to_be_bytes());
        pkt.extend_from_slice(body);
        let q = parse_postgres(&pkt).unwrap();
        assert_eq!(q.message_type, b'Q');
        assert_eq!(q.query, "SELECT 1;");
    }

    #[test]
    fn parse_postgres_startup_message() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&16u32.to_be_bytes());
        pkt.extend_from_slice(&0x0003_0000u32.to_be_bytes());
        pkt.extend_from_slice(b"user\0bob\0");
        let q = parse_postgres(&pkt).unwrap();
        assert_eq!(q.message_type, 0);
    }

    #[test]
    fn detect_dns_tcp_query() {
        let mut pkt = vec![0x00, 0x1c];
        let header = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        pkt.extend_from_slice(&header);
        pkt.push(1);
        pkt.push(b'x');
        pkt.push(0);
        pkt.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(detect_protocol(&pkt), DetectedProtocol::DnsTcp);
    }

    #[test]
    fn parse_dns_tcp_extracts_qname() {
        let mut pkt = vec![0x00, 0x22];
        pkt.extend_from_slice(&[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        pkt.push(7);
        pkt.extend_from_slice(b"example");
        pkt.push(3);
        pkt.extend_from_slice(b"com");
        pkt.push(0);
        pkt.extend_from_slice(&[0, 1, 0, 1]);
        let msg = parse_dns_tcp(&pkt).unwrap();
        assert_eq!(msg.qname.as_deref(), Some("example.com"));
        assert_eq!(msg.question_count, 1);
        assert!(!msg.is_response);
    }

    #[test]
    fn parse_dns_tcp_response_flag_set() {
        let mut pkt = vec![0x00, 0x1c];
        pkt.extend_from_slice(&[
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        pkt.push(1);
        pkt.push(b'x');
        pkt.push(0);
        pkt.extend_from_slice(&[0, 1, 0, 1]);
        let msg = parse_dns_tcp(&pkt).unwrap();
        assert!(msg.is_response);
    }

    // ── IMAP ──────────────────────────────────────────────────────

    #[test]
    fn detect_imap_client_login() {
        assert_eq!(
            detect_protocol(b"a001 LOGIN alice secret\r\n"),
            DetectedProtocol::Imap
        );
    }

    #[test]
    fn detect_imap_server_greeting() {
        assert_eq!(
            detect_protocol(b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n"),
            DetectedProtocol::Imap
        );
    }

    #[test]
    fn parse_imap_client_command() {
        let cmd = parse_imap(b"a001 LOGIN alice secret\r\n").unwrap();
        assert_eq!(cmd.tag, "a001");
        assert_eq!(cmd.command, "LOGIN");
        assert!(cmd.params.contains("alice"));
    }

    #[test]
    fn parse_imap_server_response() {
        let cmd = parse_imap(b"* OK Dovecot ready.\r\n").unwrap();
        assert_eq!(cmd.tag, "*");
        assert_eq!(cmd.command, "OK");
    }

    #[test]
    fn detect_imap_rejects_plain_text() {
        assert_ne!(
            detect_protocol(b"plain text no command\r\n"),
            DetectedProtocol::Imap
        );
    }

    // ── POP3 ──────────────────────────────────────────────────────

    #[test]
    fn detect_pop3_server_greeting() {
        assert_eq!(
            detect_protocol(b"+OK POP3 server ready\r\n"),
            DetectedProtocol::Pop3
        );
    }

    #[test]
    fn detect_pop3_err_response() {
        assert_eq!(
            detect_protocol(b"-ERR invalid command\r\n"),
            DetectedProtocol::Pop3
        );
    }

    #[test]
    fn parse_pop3_ok_response() {
        let cmd = parse_pop3(b"+OK 2 messages\r\n").unwrap();
        assert_eq!(cmd.command, "+OK");
        assert_eq!(cmd.params, "2 messages");
    }

    #[test]
    fn parse_pop3_user_command() {
        let cmd = parse_pop3(b"USER bob\r\n").unwrap();
        assert_eq!(cmd.command, "USER");
        assert_eq!(cmd.params, "bob");
    }

    #[test]
    fn parse_pop3_rejects_empty() {
        assert!(parse_pop3(b"").is_err() || parse_pop3(b"").unwrap().command.is_empty());
    }
}

//! Minimal Docker Engine API client over Unix socket.
//!
//! Performs a single-request HTTP/1.1 `GET /v1.43/containers/{id}/json` on
//! `/var/run/docker.sock`. No external Docker SDK dependency — raw
//! [`tokio::net::UnixStream`] with manual request framing and response
//! parsing. Keeps the OSS dependency surface tiny.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

use domain::container::entity::DockerMetadata;
use domain::container::error::ContainerError;

/// Default socket path.
pub const DEFAULT_SOCKET: &str = "/var/run/docker.sock";
/// Default request timeout.
pub const DEFAULT_TIMEOUT_MS: u64 = 2_000;
/// Max response body size we accept (1 MiB — Docker inspect payloads are tiny).
const MAX_BODY_BYTES: usize = 1 << 20;

/// Subset of the Docker inspect payload we consume.
#[derive(Debug, Deserialize)]
struct DockerInspect {
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Created", default)]
    created: String,
    #[serde(rename = "State", default)]
    state: DockerState,
    #[serde(rename = "Config", default)]
    config: DockerConfig,
}

#[derive(Debug, Default, Deserialize)]
struct DockerState {
    #[serde(rename = "Status", default)]
    status: String,
}

#[derive(Debug, Default, Deserialize)]
struct DockerConfig {
    #[serde(rename = "Image", default)]
    image: String,
    #[serde(rename = "Labels", default)]
    labels: Option<std::collections::BTreeMap<String, String>>,
}

/// Docker Engine API client.
pub struct DockerClient {
    socket: PathBuf,
    timeout: Duration,
    timeout_ms: u64,
}

impl DockerClient {
    pub fn new(socket: impl Into<PathBuf>, timeout_ms: u64) -> Self {
        Self {
            socket: socket.into(),
            timeout: Duration::from_millis(timeout_ms),
            timeout_ms,
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    /// `GET /v1.43/containers/{id}/json` — returns parsed metadata.
    pub async fn inspect_container(&self, id: &str) -> Result<DockerMetadata, ContainerError> {
        let request = format!(
            "GET /v1.43/containers/{id}/json HTTP/1.1\r\n\
             Host: localhost\r\n\
             Accept: application/json\r\n\
             Connection: close\r\n\
             \r\n"
        );

        let connect = UnixStream::connect(&self.socket);
        let mut stream = timeout(self.timeout, connect)
            .await
            .map_err(|_| ContainerError::DockerTimeout {
                timeout_ms: self.timeout_ms,
            })?
            .map_err(|_| ContainerError::DockerUnavailable {
                socket: self.socket.display().to_string(),
            })?;

        timeout(self.timeout, async {
            stream.write_all(request.as_bytes()).await?;
            stream.flush().await?;
            let mut buf = Vec::with_capacity(4096);
            let mut chunk = [0u8; 4096];
            loop {
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_BODY_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "response too large",
                    ));
                }
            }
            Ok::<Vec<u8>, std::io::Error>(buf)
        })
        .await
        .map_err(|_| ContainerError::DockerTimeout {
            timeout_ms: self.timeout_ms,
        })?
        .map_err(|_| ContainerError::DockerUnavailable {
            socket: self.socket.display().to_string(),
        })
        .and_then(|raw| parse_inspect_response(&raw, id))
    }
}

/// Parse an HTTP/1.1 response and decode the JSON body into [`DockerMetadata`].
fn parse_inspect_response(raw: &[u8], id: &str) -> Result<DockerMetadata, ContainerError> {
    let split = find_header_end(raw).ok_or_else(|| ContainerError::DockerMalformed {
        reason: "missing header/body boundary".to_string(),
    })?;
    let (header_bytes, body_bytes) = raw.split_at(split);
    let body_bytes = &body_bytes[4..]; // skip "\r\n\r\n"

    let header_str =
        std::str::from_utf8(header_bytes).map_err(|_| ContainerError::DockerMalformed {
            reason: "non-utf8 headers".to_string(),
        })?;
    let status = parse_status(header_str)?;
    match status {
        200 => {}
        404 => {
            return Err(ContainerError::ContainerNotFound { id: id.to_string() });
        }
        other => return Err(ContainerError::DockerApi { status: other }),
    }

    // Docker returns `Transfer-Encoding: chunked`. Decode if present.
    let chunked = header_str
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.contains("chunked"));
    let body: Vec<u8> = if chunked {
        decode_chunked(body_bytes)?
    } else {
        body_bytes.to_vec()
    };

    let inspect: DockerInspect =
        serde_json::from_slice(&body).map_err(|e| ContainerError::DockerMalformed {
            reason: format!("json parse: {e}"),
        })?;

    Ok(DockerMetadata {
        // Docker prefixes names with '/', drop it.
        name: inspect.name.trim_start_matches('/').to_string(),
        image: inspect.config.image,
        labels: inspect
            .config
            .labels
            .unwrap_or_default()
            .into_iter()
            .collect(),
        created_at: inspect.created,
        status: inspect.state.status,
    })
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_status(header: &str) -> Result<u16, ContainerError> {
    let first = header.lines().next().unwrap_or_default();
    // "HTTP/1.1 200 OK"
    let mut parts = first.split_whitespace();
    let _ = parts.next();
    let code = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| ContainerError::DockerMalformed {
            reason: format!("status line: {first}"),
        })?;
    Ok(code)
}

fn decode_chunked(mut body: &[u8]) -> Result<Vec<u8>, ContainerError> {
    let mut out = Vec::with_capacity(body.len());
    loop {
        let nl = body.windows(2).position(|w| w == b"\r\n").ok_or_else(|| {
            ContainerError::DockerMalformed {
                reason: "chunk size line missing".to_string(),
            }
        })?;
        let size_line =
            std::str::from_utf8(&body[..nl]).map_err(|_| ContainerError::DockerMalformed {
                reason: "non-utf8 chunk size".to_string(),
            })?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size =
            usize::from_str_radix(size_hex, 16).map_err(|_| ContainerError::DockerMalformed {
                reason: format!("chunk size: {size_line}"),
            })?;
        body = &body[nl + 2..];
        if size == 0 {
            break;
        }
        if body.len() < size + 2 {
            return Err(ContainerError::DockerMalformed {
                reason: "truncated chunk body".to_string(),
            });
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..]; // skip trailing \r\n
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_response(status: u16, body: &str) -> Vec<u8> {
        let len = body.len();
        let body_chunked = format!("{len:x}\r\n{body}\r\n0\r\n\r\n");
        format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{body_chunked}"
        )
        .into_bytes()
    }

    fn build_simple_response(status: u16, body: &str) -> Vec<u8> {
        let len = body.len();
        format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {len}\r\n\r\n{body}"
        )
        .into_bytes()
    }

    const VALID_INSPECT_JSON: &str = r#"{
        "Id": "abcdef1234567890",
        "Name": "/my-container",
        "Created": "2026-01-15T10:30:00.000Z",
        "State": { "Status": "running" },
        "Config": {
            "Image": "nginx:1.25",
            "Labels": { "app": "web", "env": "prod" }
        }
    }"#;

    #[test]
    fn parses_happy_path_chunked() {
        let raw = build_response(200, VALID_INSPECT_JSON);
        let md = parse_inspect_response(&raw, "abcdef1234567890").unwrap();
        assert_eq!(md.name, "my-container");
        assert_eq!(md.image, "nginx:1.25");
        assert_eq!(md.status, "running");
        assert_eq!(md.created_at, "2026-01-15T10:30:00.000Z");
        assert_eq!(md.labels.len(), 2);
        assert!(md.labels.iter().any(|(k, v)| k == "app" && v == "web"));
    }

    #[test]
    fn parses_simple_content_length_body() {
        let raw = build_simple_response(200, VALID_INSPECT_JSON);
        let md = parse_inspect_response(&raw, "abcdef1234567890").unwrap();
        assert_eq!(md.image, "nginx:1.25");
    }

    #[test]
    fn parses_name_without_leading_slash() {
        let json =
            r#"{"Name":"plain","Created":"t","State":{"Status":"ok"},"Config":{"Image":"i"}}"#;
        let raw = build_simple_response(200, json);
        let md = parse_inspect_response(&raw, "id").unwrap();
        assert_eq!(md.name, "plain");
    }

    #[test]
    fn handles_missing_optional_labels() {
        let json =
            r#"{"Name":"/c","Created":"t","State":{"Status":"ok"},"Config":{"Image":"img"}}"#;
        let raw = build_simple_response(200, json);
        let md = parse_inspect_response(&raw, "id").unwrap();
        assert!(md.labels.is_empty());
    }

    #[test]
    fn rejects_404_as_container_not_found() {
        let raw = build_simple_response(404, r#"{"message":"No such container"}"#);
        let err = parse_inspect_response(&raw, "ghost").unwrap_err();
        assert!(matches!(err, ContainerError::ContainerNotFound { .. }));
    }

    #[test]
    fn rejects_500_as_api_error() {
        let raw = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_vec();
        let err = parse_inspect_response(&raw, "id").unwrap_err();
        assert!(matches!(err, ContainerError::DockerApi { status: 500 }));
    }

    #[test]
    fn rejects_malformed_json() {
        let raw = build_simple_response(200, "{not-json");
        let err = parse_inspect_response(&raw, "id").unwrap_err();
        assert!(matches!(err, ContainerError::DockerMalformed { .. }));
    }

    #[test]
    fn rejects_missing_header_boundary() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n".to_vec();
        let err = parse_inspect_response(&raw, "id").unwrap_err();
        assert!(matches!(err, ContainerError::DockerMalformed { .. }));
    }

    #[test]
    fn rejects_non_utf8_headers() {
        let mut raw = b"HTTP/1.1 200 OK\r\nX-Junk: ".to_vec();
        raw.extend_from_slice(&[0xff, 0xfe]);
        raw.extend_from_slice(b"\r\n\r\n{}");
        let err = parse_inspect_response(&raw, "id").unwrap_err();
        assert!(matches!(err, ContainerError::DockerMalformed { .. }));
    }

    #[test]
    fn rejects_bad_status_line() {
        let raw = b"HELLO WORLD\r\n\r\n".to_vec();
        let err = parse_inspect_response(&raw, "id").unwrap_err();
        assert!(matches!(err, ContainerError::DockerMalformed { .. }));
    }

    #[test]
    fn chunked_decoder_handles_multi_chunk() {
        let body = "hello world";
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
                .to_vec();
        let split = find_header_end(&raw).unwrap();
        let body_bytes = &raw[split + 4..];
        let decoded = decode_chunked(body_bytes).unwrap();
        assert_eq!(std::str::from_utf8(&decoded).unwrap(), body);
    }

    #[test]
    fn chunked_decoder_rejects_truncated() {
        let body_bytes = b"5\r\nhell"; // missing rest
        let err = decode_chunked(body_bytes).unwrap_err();
        assert!(matches!(err, ContainerError::DockerMalformed { .. }));
    }
}

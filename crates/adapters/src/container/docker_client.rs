//! Minimal Docker Engine API client over Unix socket.
//!
//! Performs single-request HTTP/1.1 calls - `GET /v1.43/containers/{id}/json`,
//! `GET /v1.43/containers/json`, `GET /v1.43/networks` and
//! `GET /v1.43/networks/{id}` - on `/var/run/docker.sock`. No external Docker SDK dependency - raw
//! [`tokio::net::UnixStream`] with manual request framing and response
//! parsing. Keeps the OSS dependency surface tiny.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

use domain::container::entity::DockerMetadata;
use domain::container::error::ContainerError;
use domain::learning::segmentation::{BridgeMember, BridgeNetwork, BridgeSubnet};
use ports::secondary::bridge_network_port::BridgeNetworkPort;

/// Default socket path.
pub const DEFAULT_SOCKET: &str = "/var/run/docker.sock";
/// Default request timeout.
pub const DEFAULT_TIMEOUT_MS: u64 = 2_000;
/// Max response body size we accept (1 MiB - Docker inspect payloads are tiny).
const MAX_BODY_BYTES: usize = 1 << 20;
/// Max list response we accept: a few kilobytes per container, so this
/// holds a node far denser than any Docker host runs.
const MAX_LIST_BODY_BYTES: usize = 16 << 20;

/// `{"driver":{"bridge":true}}`, percent-encoded for the query string.
const BRIDGE_DRIVER_FILTER: &str = "%7B%22driver%22%3A%7B%22bridge%22%3Atrue%7D%7D";

/// The option Docker sets on the one network that is the default bridge,
/// which is the one network its embedded resolver does not serve.
const DEFAULT_BRIDGE_OPTION: &str = "com.docker.network.bridge.default_bridge";

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

    /// `GET /v1.43/containers/{id}/json` - returns parsed metadata.
    pub async fn inspect_container(&self, id: &str) -> Result<DockerMetadata, ContainerError> {
        let raw = self
            .get(&format!("/v1.43/containers/{id}/json"), MAX_BODY_BYTES)
            .await?;
        parse_inspect_response(&raw, id)
    }

    /// `GET /v1.43/containers/json` - every running container, with its
    /// labels.
    pub async fn list_containers(&self) -> Result<Vec<ListedContainer>, ContainerError> {
        let raw = self
            .get("/v1.43/containers/json", MAX_LIST_BODY_BYTES)
            .await?;
        parse_list_response(&raw)
    }

    /// `GET /v1.43/networks` filtered to the bridge driver, then
    /// `GET /v1.43/networks/{id}` for each, since only the inspect call
    /// names the containers attached.
    pub async fn bridge_networks(&self) -> Result<Vec<BridgeNetwork>, ContainerError> {
        let raw = self
            .get(
                &format!("/v1.43/networks?filters={BRIDGE_DRIVER_FILTER}"),
                MAX_LIST_BODY_BYTES,
            )
            .await?;
        let mut networks = Vec::new();
        for id in parse_network_list(&raw)? {
            let raw = self
                .get(&format!("/v1.43/networks/{id}"), MAX_LIST_BODY_BYTES)
                .await?;
            if let Some(network) = parse_network_inspect(&raw)? {
                networks.push(network);
            }
        }
        Ok(networks)
    }

    /// One request on a fresh connection, the whole response read back.
    async fn get(&self, path: &str, max_bytes: usize) -> Result<Vec<u8>, ContainerError> {
        let request = format!(
            "GET {path} HTTP/1.1\r\n\
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
                if buf.len() > max_bytes {
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
    }
}

/// One running container as the list call reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedContainer {
    /// Container id, in full.
    pub id: String,
    /// Name the runtime gave it, without the leading slash.
    pub name: String,
    /// Every label it carries.
    pub labels: Vec<(String, String)>,
}

#[derive(Debug, Deserialize)]
struct WireListed {
    #[serde(rename = "Id", default)]
    id: String,
    #[serde(rename = "Names", default)]
    names: Vec<String>,
    #[serde(rename = "Labels", default)]
    labels: Option<std::collections::BTreeMap<String, String>>,
}

/// Split a whole response into its status and its decoded body.
fn split_response(raw: &[u8]) -> Result<(u16, Vec<u8>), ContainerError> {
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

    // Docker returns `Transfer-Encoding: chunked`. Decode if present.
    let chunked = header_str
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.contains("chunked"));
    let body: Vec<u8> = if chunked && status == 200 {
        decode_chunked(body_bytes)?
    } else {
        body_bytes.to_vec()
    };
    Ok((status, body))
}

/// Parse the list call's response.
fn parse_list_response(raw: &[u8]) -> Result<Vec<ListedContainer>, ContainerError> {
    let (status, body) = split_response(raw)?;
    if status != 200 {
        return Err(ContainerError::DockerApi { status });
    }
    let listed: Vec<WireListed> =
        serde_json::from_slice(&body).map_err(|e| ContainerError::DockerMalformed {
            reason: format!("json parse: {e}"),
        })?;
    Ok(listed
        .into_iter()
        .filter(|container| !container.id.is_empty())
        .map(|container| ListedContainer {
            id: container.id,
            name: container
                .names
                .first()
                .map(|name| name.trim_start_matches('/').to_string())
                .unwrap_or_default(),
            labels: container.labels.unwrap_or_default().into_iter().collect(),
        })
        .collect())
}

#[async_trait]
impl BridgeNetworkPort for DockerClient {
    async fn bridge_networks(&self) -> Result<Vec<BridgeNetwork>, ContainerError> {
        DockerClient::bridge_networks(self).await
    }
}

#[derive(Debug, Deserialize)]
struct WireNetworkId {
    #[serde(rename = "Id", default)]
    id: String,
}

#[derive(Debug, Deserialize)]
struct WireNetwork {
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Driver", default)]
    driver: String,
    #[serde(rename = "IPAM", default)]
    ipam: WireIpam,
    #[serde(rename = "Options", default)]
    options: Option<BTreeMap<String, String>>,
    #[serde(rename = "Containers", default)]
    containers: Option<BTreeMap<String, WireEndpoint>>,
}

#[derive(Debug, Default, Deserialize)]
struct WireIpam {
    #[serde(rename = "Config", default)]
    config: Option<Vec<WireIpamConfig>>,
}

#[derive(Debug, Deserialize)]
struct WireIpamConfig {
    #[serde(rename = "Subnet", default)]
    subnet: String,
    #[serde(rename = "Gateway", default)]
    gateway: String,
}

#[derive(Debug, Deserialize)]
struct WireEndpoint {
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "IPv4Address", default)]
    ipv4: String,
    #[serde(rename = "IPv6Address", default)]
    ipv6: String,
}

fn decode_json<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T, ContainerError> {
    let (status, body) = split_response(raw)?;
    if status != 200 {
        return Err(ContainerError::DockerApi { status });
    }
    serde_json::from_slice(&body).map_err(|e| ContainerError::DockerMalformed {
        reason: format!("json parse: {e}"),
    })
}

/// The ids the network list call returned.
fn parse_network_list(raw: &[u8]) -> Result<Vec<String>, ContainerError> {
    let listed: Vec<WireNetworkId> = decode_json(raw)?;
    Ok(listed
        .into_iter()
        .map(|network| network.id)
        .filter(|id| !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric()))
        .collect())
}

/// One network's inspect payload, or `None` when it is not a bridge.
fn parse_network_inspect(raw: &[u8]) -> Result<Option<BridgeNetwork>, ContainerError> {
    let network: WireNetwork = decode_json(raw)?;
    if network.driver != "bridge" {
        return Ok(None);
    }
    let subnets = network
        .ipam
        .config
        .unwrap_or_default()
        .into_iter()
        .filter(|config| !config.subnet.is_empty())
        .map(|config| parse_subnet(&config.subnet, &config.gateway))
        .collect::<Result<Vec<_>, _>>()?;
    let default_bridge = network
        .options
        .as_ref()
        .and_then(|options| options.get(DEFAULT_BRIDGE_OPTION))
        .is_some_and(|value| value == "true");
    let members = network
        .containers
        .unwrap_or_default()
        .into_iter()
        .map(|(id, endpoint)| BridgeMember {
            id,
            name: endpoint.name,
            addresses: [endpoint.ipv4, endpoint.ipv6]
                .iter()
                .filter_map(|address| address.split('/').next())
                .filter_map(|address| address.parse::<IpAddr>().ok())
                .collect(),
        })
        .collect();
    Ok(Some(BridgeNetwork {
        name: network.name,
        subnets,
        embedded_dns: !default_bridge,
        members,
    }))
}

fn parse_subnet(subnet: &str, gateway: &str) -> Result<BridgeSubnet, ContainerError> {
    let malformed = || ContainerError::DockerMalformed {
        reason: format!("network subnet: {subnet}"),
    };
    let (network, prefix) = subnet.split_once('/').ok_or_else(malformed)?;
    let network: IpAddr = network.parse().map_err(|_| malformed())?;
    let prefix_len: u8 = prefix.parse().map_err(|_| malformed())?;
    let ceiling = if network.is_ipv4() { 32 } else { 128 };
    if prefix_len > ceiling {
        return Err(malformed());
    }
    Ok(BridgeSubnet {
        network,
        prefix_len,
        gateway: gateway.split('/').next().and_then(|g| g.parse().ok()),
    })
}

/// Parse an HTTP/1.1 response and decode the JSON body into [`DockerMetadata`].
fn parse_inspect_response(raw: &[u8], id: &str) -> Result<DockerMetadata, ContainerError> {
    let (status, body) = split_response(raw)?;
    match status {
        200 => {}
        404 => {
            return Err(ContainerError::ContainerNotFound { id: id.to_string() });
        }
        other => return Err(ContainerError::DockerApi { status: other }),
    }

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
    fn a_bridge_network_keeps_its_subnet_gateway_and_members() {
        let raw = build_response(
            200,
            r#"{"Name": "app", "Driver": "bridge",
                "IPAM": {"Config": [{"Subnet": "172.18.0.0/16", "Gateway": "172.18.0.1"}]},
                "Options": {},
                "Containers": {"abc123": {"Name": "web",
                    "IPv4Address": "172.18.0.2/16", "IPv6Address": ""}}}"#,
        );
        let network = parse_network_inspect(&raw)
            .expect("the payload parses")
            .expect("a bridge");
        assert_eq!(network.name, "app");
        assert!(network.embedded_dns);
        assert_eq!(network.subnets[0].cidr(), "172.18.0.0/16");
        assert_eq!(
            network.subnets[0].gateway,
            Some("172.18.0.1".parse().expect("an address"))
        );
        assert_eq!(network.members[0].name, "web");
        assert_eq!(network.members[0].id, "abc123");
        assert_eq!(
            network.members[0].addresses,
            vec!["172.18.0.2".parse::<IpAddr>().expect("an address")]
        );
    }

    #[test]
    fn the_default_bridge_has_no_embedded_resolver_and_other_drivers_are_skipped() {
        let raw = build_simple_response(
            200,
            r#"{"Name": "bridge", "Driver": "bridge",
                "IPAM": {"Config": [{"Subnet": "172.17.0.0/16"}]},
                "Options": {"com.docker.network.bridge.default_bridge": "true"}}"#,
        );
        let network = parse_network_inspect(&raw)
            .expect("the payload parses")
            .expect("a bridge");
        assert!(!network.embedded_dns);
        assert!(network.members.is_empty());
        assert_eq!(network.subnets[0].gateway, None);

        let overlay = build_simple_response(200, r#"{"Name": "swarm", "Driver": "overlay"}"#);
        assert!(parse_network_inspect(&overlay).expect("parses").is_none());
    }

    #[test]
    fn a_subnet_that_does_not_read_is_refused_rather_than_skipped() {
        let raw = build_simple_response(
            200,
            r#"{"Name": "app", "Driver": "bridge",
                "IPAM": {"Config": [{"Subnet": "172.18.0.0/40"}]}}"#,
        );
        assert!(matches!(
            parse_network_inspect(&raw),
            Err(ContainerError::DockerMalformed { .. })
        ));
    }

    #[test]
    fn the_network_list_keeps_only_ids_safe_in_a_path() {
        let raw = build_simple_response(200, r#"[{"Id": "abc123"}, {"Id": "../x"}, {"Id": ""}]"#);
        assert_eq!(
            parse_network_list(&raw).expect("parses"),
            vec!["abc123".to_string()]
        );
    }

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

    #[test]
    fn the_list_keeps_id_name_and_labels() {
        let body = r#"[{"Id":"abc","Names":["/web"],"Labels":{"a":"1"}},{"Id":"def","Names":[],"Labels":null},{"Names":["/ghost"]}]"#;
        let listed = parse_list_response(&build_response(200, body)).unwrap();
        assert_eq!(
            listed,
            vec![
                ListedContainer {
                    id: "abc".to_string(),
                    name: "web".to_string(),
                    labels: vec![("a".to_string(), "1".to_string())],
                },
                ListedContainer {
                    id: "def".to_string(),
                    name: String::new(),
                    labels: Vec::new(),
                },
            ]
        );
        assert!(matches!(
            parse_list_response(&build_simple_response(500, "{}")),
            Err(ContainerError::DockerApi { status: 500 })
        ));
    }
}

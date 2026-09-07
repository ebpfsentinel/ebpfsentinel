//! Posting one heartbeat over HTTPS.
//!
//! The destination is a build-time constant rather than a configuration key.
//! A build made from these sources carries no endpoint at all and the beacon
//! refuses to exist, so an agent compiled by anybody but us reports nowhere;
//! our own release workflow supplies `EBPFSENTINEL_TELEMETRY_ENDPOINT` and the
//! constant is baked in. This is not a secret and is not treated as one: it is
//! in the binary, `strings` will find it, and the point is only that the
//! sources do not name it and a community build is inert.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use domain::telemetry::entity::Heartbeat;
use domain::telemetry::error::TelemetryError;
use ports::secondary::telemetry_port::TelemetryTransport;

/// How long to wait for the connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait for the whole exchange.
///
/// Short on purpose: a beat that has not landed in ten seconds has failed, and
/// the next one is half an hour away.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Where this build reports, if it reports anywhere.
///
/// Supplied at compile time and absent from the sources. `None` is the normal
/// answer for a build made from a checkout.
pub const BUILT_IN_ENDPOINT: Option<&str> = option_env!("EBPFSENTINEL_TELEMETRY_ENDPOINT");

/// Posts beats to one endpoint.
#[derive(Debug)]
pub struct HttpTelemetryBeacon {
    client: reqwest::Client,
    endpoint: String,
}

impl HttpTelemetryBeacon {
    /// Builds the beacon this binary was compiled with.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::NotConfigured`] when the build carries no
    /// endpoint, which is what every build from source does.
    pub fn from_build() -> Result<Self, TelemetryError> {
        let endpoint = BUILT_IN_ENDPOINT.ok_or_else(|| {
            TelemetryError::NotConfigured("this build carries no telemetry endpoint".to_string())
        })?;

        Self::new(endpoint)
    }

    /// Builds a beacon pointed at one endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::NotConfigured`] when the address is not an
    /// absolute HTTPS URL, or when the client cannot be built. Plain HTTP is
    /// refused off loopback before a socket exists, so a mistyped endpoint
    /// cannot put the beat on the wire in clear.
    pub fn new(endpoint: &str) -> Result<Self, TelemetryError> {
        let endpoint = validate_endpoint(endpoint)?;

        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .use_rustls_tls()
            .build()
            .map_err(|e| {
                TelemetryError::Transport(format!("the HTTP client could not be built: {e}"))
            })?;

        Ok(Self { client, endpoint })
    }
}

impl TelemetryTransport for HttpTelemetryBeacon {
    fn send<'a>(
        &'a self,
        beat: Heartbeat,
    ) -> Pin<Box<dyn Future<Output = Result<(), TelemetryError>> + Send + 'a>> {
        Box::pin(async move {
            let response = self
                .client
                .post(&self.endpoint)
                .json(&beat)
                .send()
                .await
                .map_err(|e| TelemetryError::Transport(format!("the beat was not sent: {e}")))?;

            // The status and nothing else: the answer is not read, so there is
            // no body this agent can be told to act on.
            if response.status().is_success() {
                Ok(())
            } else {
                Err(TelemetryError::Transport(format!(
                    "the endpoint answered {}",
                    response.status().as_u16()
                )))
            }
        })
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

/// Refuses anything but an absolute HTTPS URL, allowing loopback in clear so a
/// test can stand an endpoint up beside the agent.
fn validate_endpoint(raw: &str) -> Result<String, TelemetryError> {
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        return Err(TelemetryError::NotConfigured(
            "the telemetry endpoint is empty".to_string(),
        ));
    }

    if trimmed.chars().any(char::is_whitespace) {
        return Err(TelemetryError::NotConfigured(
            "the telemetry endpoint carries whitespace".to_string(),
        ));
    }

    let host = if let Some(rest) = trimmed.strip_prefix("https://") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        if !is_loopback(rest) {
            return Err(TelemetryError::NotConfigured(
                "the telemetry endpoint is plain HTTP and is not loopback".to_string(),
            ));
        }
        rest
    } else {
        return Err(TelemetryError::NotConfigured(
            "the telemetry endpoint is not an http or https URL".to_string(),
        ));
    };

    if host.is_empty() || host.starts_with('/') {
        return Err(TelemetryError::NotConfigured(
            "the telemetry endpoint has no host".to_string(),
        ));
    }

    Ok(trimmed.to_string())
}

/// Whether the authority at the head of a URL names this machine.
fn is_loopback(rest: &str) -> bool {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();

    // Only a trailing all-digit segment is a port, so a bracketed IPv6 literal
    // keeps its own colons instead of losing its last group to the split.
    let host = match authority.rsplit_once(':') {
        Some((head, port))
            if !head.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            head
        }
        _ => authority,
    };

    matches!(host, "localhost" | "[::1]") || host.starts_with("127.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_build_from_source_reports_nowhere() {
        // The whole point of the build-time constant: a checkout compiled by
        // anybody carries no endpoint, so the beacon refuses to exist. And when
        // our own workflow does supply one, a mistyped value fails here rather
        // than on every machine in the field.
        match BUILT_IN_ENDPOINT {
            None => assert!(matches!(
                HttpTelemetryBeacon::from_build(),
                Err(TelemetryError::NotConfigured(_))
            )),
            Some(endpoint) => assert!(
                HttpTelemetryBeacon::new(endpoint).is_ok(),
                "this build was given an endpoint it cannot use: {endpoint}"
            ),
        }
    }

    #[test]
    fn plain_http_is_refused_before_a_socket_exists() {
        assert!(HttpTelemetryBeacon::new("http://telemetry.example.test/v1").is_err());
        assert!(HttpTelemetryBeacon::new("https://telemetry.example.test/v1").is_ok());
    }

    #[test]
    fn an_endpoint_beside_the_agent_is_allowed_in_clear() {
        assert!(HttpTelemetryBeacon::new("http://127.0.0.1:8080/v1").is_ok());
        assert!(HttpTelemetryBeacon::new("http://localhost:8080/v1").is_ok());
        assert!(HttpTelemetryBeacon::new("http://[::1]:8080/v1").is_ok());
    }

    #[test]
    fn anything_that_is_not_a_url_is_refused() {
        assert!(HttpTelemetryBeacon::new("").is_err());
        assert!(HttpTelemetryBeacon::new("telemetry.example.test").is_err());
        assert!(HttpTelemetryBeacon::new("https://").is_err());
        assert!(HttpTelemetryBeacon::new("https:///v1").is_err());
        assert!(HttpTelemetryBeacon::new("https://host /v1").is_err());
        assert!(HttpTelemetryBeacon::new("ftp://host/v1").is_err());
    }

    #[test]
    fn the_endpoint_is_readable_so_the_boot_line_can_name_it() {
        let beacon = HttpTelemetryBeacon::new("https://telemetry.example.test/v1").expect("built");
        assert_eq!(beacon.endpoint(), "https://telemetry.example.test/v1");
    }
}

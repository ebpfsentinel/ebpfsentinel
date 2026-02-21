use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use domain::common::error::DomainError;
use domain::threatintel::entity::FeedConfig;
use ports::secondary::feed_source::FeedSource;

/// Maximum feed response size: 100 MiB. Prevents OOM from
/// compromised or misconfigured feeds returning unbounded data.
const MAX_FEED_RESPONSE_SIZE: usize = 100 * 1024 * 1024;

/// HTTP-based feed fetcher using reqwest.
///
/// Supports custom auth headers and timeouts. This is the primary adapter
/// for downloading threat intelligence feeds from any HTTP/HTTPS source.
pub struct HttpFeedFetcher {
    client: reqwest::Client,
}

impl HttpFeedFetcher {
    /// Create a new fetcher with default settings (30s timeout).
    pub fn new() -> Result<Self, DomainError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("ebpfsentinel-agent/0.1")
            .build()
            .map_err(|e| DomainError::EngineError(format!("HTTP client init failed: {e}")))?;

        Ok(Self { client })
    }

    /// Create with a custom reqwest client (for testing or advanced config).
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    async fn do_fetch(&self, config: &FeedConfig) -> Result<Vec<u8>, DomainError> {
        let mut request = self.client.get(&config.url);

        // Apply optional auth header
        if let Some(ref auth) = config.auth_header
            && let Some((name, value)) = auth.split_once(':')
        {
            request = request.header(name.trim(), value.trim());
        }

        let mut response = request.send().await.map_err(|e| {
            DomainError::EngineError(format!("feed fetch failed for '{}': {e}", config.id))
        })?;

        if !response.status().is_success() {
            return Err(DomainError::EngineError(format!(
                "feed '{}' returned HTTP {}",
                config.id,
                response.status()
            )));
        }

        // Read response body in chunks with a size cap to prevent OOM
        // On 64-bit, u64→usize never truncates; on 32-bit we saturate to usize::MAX
        // which is fine since it will exceed MAX_FEED_RESPONSE_SIZE and be rejected.
        let content_length: usize = response
            .content_length()
            .unwrap_or(0)
            .try_into()
            .unwrap_or(usize::MAX);

        if content_length > MAX_FEED_RESPONSE_SIZE {
            return Err(DomainError::EngineError(format!(
                "feed '{}' response too large: {} bytes (max {} bytes)",
                config.id, content_length, MAX_FEED_RESPONSE_SIZE
            )));
        }

        let mut body = Vec::with_capacity(content_length.min(MAX_FEED_RESPONSE_SIZE));
        while let Some(chunk) = response.chunk().await.map_err(|e| {
            DomainError::EngineError(format!("feed '{}' body read failed: {e}", config.id))
        })? {
            if body.len() + chunk.len() > MAX_FEED_RESPONSE_SIZE {
                return Err(DomainError::EngineError(format!(
                    "feed '{}' response exceeded {} byte limit",
                    config.id, MAX_FEED_RESPONSE_SIZE
                )));
            }
            body.extend_from_slice(&chunk);
        }

        Ok(body)
    }
}

impl Default for HttpFeedFetcher {
    fn default() -> Self {
        Self::new().expect("default HTTP client should build")
    }
}

impl FeedSource for HttpFeedFetcher {
    fn fetch_feed<'a>(
        &'a self,
        config: &'a FeedConfig,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DomainError>> + Send + 'a>> {
        Box::pin(self.do_fetch(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_feed_fetcher_is_send_sync() {
        fn _assert<T: Send + Sync>() {}
        _assert::<HttpFeedFetcher>();
    }

    #[test]
    fn http_feed_fetcher_implements_feed_source() {
        fn _assert<T: FeedSource>() {}
        _assert::<HttpFeedFetcher>();
    }

    #[test]
    fn default_constructs() {
        let fetcher = HttpFeedFetcher::default();
        let _ = fetcher;
    }
}

use std::future::Future;
use std::pin::Pin;

use domain::common::error::DomainError;
use domain::threatintel::entity::FeedConfig;

/// Secondary port for downloading threat intelligence feed data.
///
/// Uses `Pin<Box<dyn Future>>` return type (instead of RPITIT) so the trait
/// is dyn-compatible and can be used as `Arc<dyn FeedSource>`.
pub trait FeedSource: Send + Sync {
    /// Fetch raw feed data from the configured URL.
    /// Returns the raw bytes of the feed response body.
    fn fetch_feed<'a>(
        &'a self,
        config: &'a FeedConfig,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DomainError>> + Send + 'a>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummySource;
    impl FeedSource for DummySource {
        fn fetch_feed<'a>(
            &'a self,
            _config: &'a FeedConfig,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DomainError>> + Send + 'a>> {
            Box::pin(async { Ok(vec![]) })
        }
    }

    #[test]
    fn feed_source_is_dyn_compatible() {
        let source: Box<dyn FeedSource> = Box::new(DummySource);
        let _ = source;
    }
}

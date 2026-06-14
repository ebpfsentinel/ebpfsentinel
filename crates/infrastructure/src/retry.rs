use std::time::Duration;

use domain::common::error::DomainError;

/// Configuration for retry with exponential backoff.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retries (after the initial attempt).
    pub max_retries: usize,
    /// Backoff delays between retries. If fewer entries than `max_retries`,
    /// the last entry is repeated.
    pub backoff_schedule: Vec<Duration>,
    /// Timeout per individual attempt.
    pub timeout: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff_schedule: vec![
                Duration::from_secs(1),
                Duration::from_secs(5),
                Duration::from_secs(30),
            ],
            timeout: Duration::from_secs(10),
        }
    }
}

impl RetryConfig {
    fn backoff_for(&self, attempt: usize) -> Duration {
        self.backoff_schedule
            .get(attempt)
            .copied()
            .unwrap_or_else(|| {
                self.backoff_schedule
                    .last()
                    .copied()
                    .unwrap_or(Duration::from_secs(1))
            })
    }
}

/// Execute an async operation with retry and exponential backoff.
///
/// The closure `f` is called up to `1 + max_retries` times. Each attempt is
/// wrapped in a per-attempt timeout. On failure, the function sleeps for the
/// backoff duration before retrying.
pub async fn retry_with_backoff<F, Fut>(config: &RetryConfig, mut f: F) -> Result<(), DomainError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), DomainError>>,
{
    let mut last_error = None;

    for attempt in 0..=config.max_retries {
        let result = tokio::time::timeout(config.timeout, f()).await;

        match result {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(e)) => {
                last_error = Some(e);
            }
            Err(_elapsed) => {
                last_error = Some(DomainError::EngineError("attempt timed out".to_string()));
            }
        }

        // Sleep before next retry (but not after the last attempt)
        if attempt < config.max_retries {
            let delay = config.backoff_for(attempt);
            tokio::time::sleep(delay).await;
        }
    }

    Err(last_error.unwrap_or_else(|| DomainError::EngineError("all retries exhausted".to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn succeeds_first_try() {
        let config = RetryConfig {
            max_retries: 3,
            backoff_schedule: vec![Duration::from_millis(1)],
            timeout: Duration::from_secs(1),
        };
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = Arc::clone(&calls);

        let result = retry_with_backoff(&config, || {
            calls_clone.fetch_add(1, Ordering::Relaxed);
            async { Ok(()) }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn succeeds_after_retry() {
        let config = RetryConfig {
            max_retries: 3,
            backoff_schedule: vec![Duration::from_millis(1)],
            timeout: Duration::from_secs(1),
        };
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = Arc::clone(&calls);

        let result = retry_with_backoff(&config, || {
            let attempt = calls_clone.fetch_add(1, Ordering::Relaxed);
            async move {
                if attempt < 2 {
                    Err(DomainError::EngineError("transient".to_string()))
                } else {
                    Ok(())
                }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(calls.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn all_retries_exhausted() {
        let config = RetryConfig {
            max_retries: 2,
            backoff_schedule: vec![Duration::from_millis(1)],
            timeout: Duration::from_secs(1),
        };
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = Arc::clone(&calls);

        let result = retry_with_backoff(&config, || {
            calls_clone.fetch_add(1, Ordering::Relaxed);
            async { Err(DomainError::EngineError("permanent".to_string())) }
        })
        .await;

        assert!(result.is_err());
        // 1 initial + 2 retries = 3 total
        assert_eq!(calls.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn timeout_enforced() {
        let config = RetryConfig {
            max_retries: 0,
            backoff_schedule: vec![Duration::from_millis(1)],
            timeout: Duration::from_millis(10),
        };

        let result = retry_with_backoff(&config, || async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        })
        .await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("timed out"), "got: {err_msg}");
    }

    #[tokio::test]
    async fn backoff_schedule_respected() {
        let config = RetryConfig {
            max_retries: 2,
            backoff_schedule: vec![Duration::from_millis(50), Duration::from_millis(100)],
            timeout: Duration::from_secs(1),
        };

        let start = tokio::time::Instant::now();
        let _ = retry_with_backoff(&config, || async {
            Err(DomainError::EngineError("fail".to_string()))
        })
        .await;
        let elapsed = start.elapsed();

        // Should have waited at least 50ms + 100ms = 150ms
        assert!(
            elapsed >= Duration::from_millis(140),
            "elapsed: {elapsed:?}"
        );
    }
}

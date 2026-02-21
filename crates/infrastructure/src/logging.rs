use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::{ConfigError, LogFormat, LogLevel};

/// Initialize structured logging to stdout.
///
/// - `LogFormat::Json`: flattened JSON (production, log aggregator compatible).
/// - `LogFormat::Text`: human-readable colored output (development).
///
/// Uses `RUST_LOG` env var if set, otherwise falls back to the given `level`.
/// Must be called exactly once at startup.
pub fn init_logging(level: LogLevel, format: LogFormat) -> Result<(), ConfigError> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.as_str()));

    let registry = tracing_subscriber::registry().with(env_filter);

    match format {
        LogFormat::Json => registry
            .with(
                fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_target(true)
                    .with_thread_ids(false)
                    .with_ansi(false),
            )
            .init(),
        LogFormat::Text => registry
            .with(fmt::layer().pretty().with_target(true).with_ansi(true))
            .init(),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_level_as_str_is_valid_env_filter() {
        // Verify that LogLevel::as_str() produces valid EnvFilter strings.
        for level in [
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace,
        ] {
            assert!(
                EnvFilter::try_new(level.as_str()).is_ok(),
                "{} should be a valid filter",
                level.as_str()
            );
        }
    }
}

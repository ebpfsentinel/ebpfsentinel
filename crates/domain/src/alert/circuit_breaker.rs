use std::time::{Duration, Instant};

/// Circuit breaker state for alert sender destinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation — all attempts allowed.
    Closed = 0,
    /// Single probe attempt allowed after open duration elapsed.
    HalfOpen = 1,
    /// All attempts blocked until open duration elapses.
    Open = 2,
}

/// Circuit breaker that tracks consecutive failures and temporarily blocks
/// attempts when the failure threshold is reached.
///
/// Transitions: Closed → Open (after `failure_threshold` consecutive failures)
/// → `HalfOpen` (after `open_duration` elapsed) → Closed (on success) or Open (on failure).
#[derive(Debug)]
pub struct CircuitBreaker {
    state: CircuitState,
    failure_count: usize,
    failure_threshold: usize,
    open_duration: Duration,
    opened_at: Option<Instant>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given threshold and open duration.
    pub fn new(failure_threshold: usize, open_duration: Duration) -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            failure_threshold,
            open_duration,
            opened_at: None,
        }
    }

    /// Check if an attempt is allowed and transition Open → `HalfOpen` if the
    /// open duration has elapsed.
    pub fn can_attempt(&mut self) -> bool {
        match self.state {
            CircuitState::Closed | CircuitState::HalfOpen => true,
            CircuitState::Open => {
                if let Some(opened_at) = self.opened_at {
                    if opened_at.elapsed() >= self.open_duration {
                        self.state = CircuitState::HalfOpen;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        }
    }

    /// Record a successful attempt — resets the circuit breaker to Closed.
    pub fn record_success(&mut self) {
        self.state = CircuitState::Closed;
        self.failure_count = 0;
        self.opened_at = None;
    }

    /// Record a failed attempt — increments the failure count and opens
    /// the circuit if the threshold is reached.
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        if self.failure_count >= self.failure_threshold {
            self.state = CircuitState::Open;
            self.opened_at = Some(Instant::now());
        }
    }

    /// Current circuit state for metrics reporting.
    pub fn state(&self) -> CircuitState {
        self.state
    }
}

impl CircuitState {
    /// Numeric value for Prometheus gauge (0=closed, 1=half-open, 2=open).
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_allows_attempts() {
        let mut cb = CircuitBreaker::new(5, Duration::from_secs(60));
        assert!(cb.can_attempt());
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn failure_increments_count() {
        let mut cb = CircuitBreaker::new(5, Duration::from_secs(60));
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.can_attempt());
    }

    #[test]
    fn threshold_opens_circuit() {
        let mut cb = CircuitBreaker::new(3, Duration::from_secs(60));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn open_blocks_attempts() {
        let mut cb = CircuitBreaker::new(2, Duration::from_secs(60));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.can_attempt());
    }

    #[test]
    fn open_transitions_to_half_open_after_duration() {
        let mut cb = CircuitBreaker::new(2, Duration::from_millis(0));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Duration is 0ms, so it should immediately transition
        assert!(cb.can_attempt());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn half_open_allows_one_probe() {
        let mut cb = CircuitBreaker::new(2, Duration::from_millis(0));
        cb.record_failure();
        cb.record_failure();
        // Transition to half-open
        assert!(cb.can_attempt());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        // Half-open allows attempts
        assert!(cb.can_attempt());
    }

    #[test]
    fn half_open_success_closes_circuit() {
        let mut cb = CircuitBreaker::new(2, Duration::from_millis(0));
        cb.record_failure();
        cb.record_failure();
        cb.can_attempt(); // transition to half-open
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.can_attempt());
    }

    #[test]
    fn half_open_failure_reopens_circuit() {
        let mut cb = CircuitBreaker::new(2, Duration::from_millis(0));
        cb.record_failure();
        cb.record_failure();
        cb.can_attempt(); // transition to half-open
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Failure in half-open state: count is already at threshold,
        // so recording one more failure should reopen
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn success_resets_failure_count() {
        let mut cb = CircuitBreaker::new(3, Duration::from_secs(60));
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);

        // After reset, need 3 more failures to open
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn circuit_state_as_u8() {
        assert_eq!(CircuitState::Closed.as_u8(), 0);
        assert_eq!(CircuitState::HalfOpen.as_u8(), 1);
        assert_eq!(CircuitState::Open.as_u8(), 2);
    }
}

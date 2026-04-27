//! Bounded ring buffer of recently broadcast `Alert`s, used by the SSE
//! alerts stream to fulfil the `Last-Event-ID` resume contract.
//!
//! The buffer is shared between the alert pipeline (push side) and the
//! HTTP / SSE adapter (snapshot side) via `Arc`. Locking is brief and
//! synchronous (`std::sync::Mutex`) — the critical section never awaits.

use std::collections::VecDeque;
use std::sync::Mutex;

use domain::alert::entity::Alert;

/// Default replay window — five thousand alerts. Sized so that a client
/// reconnecting within a typical TCP keep-alive window can resume without
/// a gap, while keeping the upper bound on memory predictable
/// (~5 000 × ~2 KiB ≈ 10 MiB).
pub const DEFAULT_CAPACITY: usize = 5_000;

/// FIFO ring buffer of recently emitted alerts.
///
/// New alerts go on the back; the oldest are evicted from the front when
/// the buffer is full.
#[derive(Debug)]
pub struct AlertReplayBuffer {
    capacity: usize,
    inner: Mutex<VecDeque<Alert>>,
}

impl AlertReplayBuffer {
    /// Create a new buffer with the given capacity. A capacity of zero is
    /// promoted to `1` so `push` can never panic on an empty deque.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            capacity: cap,
            inner: Mutex::new(VecDeque::with_capacity(cap)),
        }
    }

    /// Maximum number of alerts retained.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Current number of alerts in the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        match self.inner.lock() {
            Ok(g) => g.len(),
            Err(p) => p.into_inner().len(),
        }
    }

    /// True when the buffer has no alerts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Push an alert onto the buffer, evicting the oldest entry if full.
    pub fn push(&self, alert: Alert) {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.len() >= self.capacity {
            guard.pop_front();
        }
        guard.push_back(alert);
    }

    /// Snapshot every alert with `id` strictly after `last_id`.
    ///
    /// If `last_id` is `None`, an empty vector is returned (a fresh
    /// subscriber receives only future events from the broadcast channel).
    /// If `last_id` is `Some(id)` but `id` is not in the buffer (the
    /// client missed too much), an empty vector is also returned — the
    /// client should fall back to the REST `GET /api/v1/alerts` endpoint
    /// to backfill.
    #[must_use]
    pub fn snapshot_after(&self, last_id: Option<&str>) -> Vec<Alert> {
        let Some(last) = last_id else {
            return Vec::new();
        };
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .iter()
            .position(|a| a.id == last)
            .map_or_else(Vec::new, |pos| {
                guard.iter().skip(pos + 1).cloned().collect()
            })
    }

    /// Snapshot every alert currently in the buffer (oldest → newest).
    #[must_use]
    pub fn snapshot(&self) -> Vec<Alert> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.iter().cloned().collect()
    }
}

impl Default for AlertReplayBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::{AlertReplayBuffer, DEFAULT_CAPACITY};
    use domain::alert::entity::Alert;
    use domain::common::entity::{DomainMode, RuleId, Severity};

    fn alert_with_id(id: &str) -> Alert {
        Alert {
            id: id.to_string(),
            timestamp_ns: 0,
            component: "test".to_string(),
            severity: Severity::Low,
            rule_id: RuleId(String::new()),
            action: DomainMode::Alert,
            src_addr: [0; 4],
            dst_addr: [0; 4],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            is_ipv6: false,
            message: String::new(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
            src_geo: None,
            dst_geo: None,
            confidence: None,
            threat_type: None,
            data_type: None,
            pid: None,
            tgid: None,
            direction: None,
            matched_domain: None,
            attack_type: None,
            peak_pps: None,
            current_pps: None,
            mitigation_status: None,
            total_packets: None,
            mitre_attack: None,
            ja4_fingerprint: None,
            ml_anomaly_score: None,
            ml_top_feature: None,
            ml_engine: None,
            ai_provider: None,
            ai_sni: None,
            ai_bytes_sent: None,
            ai_exfil_type: None,
            tls_threat_category: None,
            tls_pqc_status: None,
            container: None,
            container_metadata: None,
        }
    }

    #[test]
    fn default_capacity_is_five_thousand() {
        let buf = AlertReplayBuffer::default();
        assert_eq!(buf.capacity(), DEFAULT_CAPACITY);
        assert!(buf.is_empty());
    }

    #[test]
    fn push_evicts_oldest_when_full() {
        let buf = AlertReplayBuffer::new(2);
        buf.push(alert_with_id("a"));
        buf.push(alert_with_id("b"));
        buf.push(alert_with_id("c"));
        let snap = buf.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].id, "b");
        assert_eq!(snap[1].id, "c");
    }

    #[test]
    fn snapshot_after_returns_tail() {
        let buf = AlertReplayBuffer::new(8);
        for id in ["a", "b", "c", "d"] {
            buf.push(alert_with_id(id));
        }
        let tail = buf.snapshot_after(Some("b"));
        let ids: Vec<_> = tail.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, vec!["c", "d"]);
    }

    #[test]
    fn snapshot_after_unknown_id_returns_empty() {
        let buf = AlertReplayBuffer::new(8);
        buf.push(alert_with_id("a"));
        assert!(buf.snapshot_after(Some("zzz")).is_empty());
    }

    #[test]
    fn snapshot_after_none_returns_empty() {
        let buf = AlertReplayBuffer::new(8);
        buf.push(alert_with_id("a"));
        assert!(buf.snapshot_after(None).is_empty());
    }

    #[test]
    fn capacity_zero_is_promoted_to_one() {
        let buf = AlertReplayBuffer::new(0);
        assert_eq!(buf.capacity(), 1);
        buf.push(alert_with_id("a"));
        buf.push(alert_with_id("b"));
        assert_eq!(buf.snapshot().len(), 1);
    }
}

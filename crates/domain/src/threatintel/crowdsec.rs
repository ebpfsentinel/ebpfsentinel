//! CrowdSec in both directions: decisions read from a local API become
//! indicators, and what this agent blocked becomes signals written back.
//!
//! Everything here is pure. The wire shape of the local API is read and
//! written by the adapters; this module decides which decision is an
//! indicator, which alert is a signal, and what a signal carries - which is
//! also the whole of what leaves the host, so it is kept deliberately small.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::alert::entity::Alert;
use crate::common::entity::DomainMode;

use super::entity::{FeedConfig, Ioc, ThreatType};

/// Feed identifier given to the decisions read from the local API.
pub const CROWDSEC_FEED_ID: &str = "crowdsec";

/// Confidence given to a decision: the local API only answers with decisions
/// that are in force, so each one is a verdict rather than a score.
pub const DECISION_CONFIDENCE: u8 = 100;

/// Signals held between two reports, above which new sources are dropped and
/// counted rather than held.
pub const MAX_PENDING_SIGNALS: usize = 1_000;

/// Prefix of the scenario a signal is reported under.
pub const SCENARIO_PREFIX: &str = "ebpfsentinel";

/// One decision as the local API returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// `Ip`, `Range`, `Country`, `AS`, ...
    pub scope: String,
    /// The address, the range or whatever the scope names.
    pub value: String,
    /// `ban`, `captcha`, ...
    pub kind: String,
    /// The scenario that produced the decision, e.g. `crowdsecurity/ssh-bf`.
    pub scenario: String,
}

/// What a decision list held that did not become an indicator, by reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecisionSkips {
    /// Remedies other than a ban (a captcha has no meaning on a socket).
    pub not_ban: usize,
    /// Ranges wider than one address: the indicator table holds addresses.
    pub ranges: usize,
    /// Scopes that name no address at all (country, AS, username).
    pub other_scope: usize,
    /// Values that do not read as an address in their own scope.
    pub unreadable: usize,
}

impl DecisionSkips {
    /// Every decision that was not loaded.
    #[must_use]
    pub fn total(&self) -> usize {
        self.not_ban + self.ranges + self.other_scope + self.unreadable
    }
}

/// The category a CrowdSec scenario falls into.
///
/// Scenario names are free text written by whoever wrote the collection, so
/// this reads the words they are built from rather than a fixed list.
#[must_use]
pub fn scenario_threat_type(scenario: &str) -> ThreatType {
    let s = scenario.to_ascii_lowercase();
    if s.contains("scan") || s.contains("probing") || s.contains("crawl") {
        ThreatType::Scanner
    } else if s.contains("spam") {
        ThreatType::Spam
    } else if s.contains("botnet") || s.contains("c2") {
        ThreatType::C2
    } else if s.contains("malware") || s.contains("cve") || s.contains("exploit") {
        ThreatType::Malware
    } else {
        ThreatType::Other
    }
}

/// Read a `Range` decision as one address, which it is only when its prefix
/// covers the whole address.
fn single_address_range(value: &str) -> Result<Option<IpAddr>, ()> {
    let (addr, prefix) = value.split_once('/').ok_or(())?;
    let ip: IpAddr = addr.trim().parse().map_err(|_| ())?;
    let prefix: u8 = prefix.trim().parse().map_err(|_| ())?;
    let full = if ip.is_ipv4() { 32 } else { 128 };
    match prefix.cmp(&full) {
        std::cmp::Ordering::Equal => Ok(Some(ip)),
        std::cmp::Ordering::Less => Ok(None),
        std::cmp::Ordering::Greater => Err(()),
    }
}

/// Turn the decisions the local API returned into indicators for `feed`.
///
/// A ban on one address is an indicator. Everything else is counted by reason
/// and not loaded: the caller says how many were left out, so a decision that
/// does not block here is never mistaken for one that does. The list is cut at
/// the feed's `max_iocs`.
#[must_use]
pub fn decisions_to_iocs(
    decisions: &[Decision],
    feed: &FeedConfig,
    now_ns: u64,
) -> (Vec<Ioc>, DecisionSkips) {
    let mut iocs = Vec::new();
    let mut skips = DecisionSkips::default();
    for d in decisions {
        if iocs.len() >= feed.max_iocs {
            break;
        }
        if !d.kind.eq_ignore_ascii_case("ban") {
            skips.not_ban += 1;
            continue;
        }
        let ip = if d.scope.eq_ignore_ascii_case("ip") {
            let Ok(ip) = d.value.trim().parse::<IpAddr>() else {
                skips.unreadable += 1;
                continue;
            };
            ip
        } else if d.scope.eq_ignore_ascii_case("range") {
            match single_address_range(&d.value) {
                Ok(Some(ip)) => ip,
                Ok(None) => {
                    skips.ranges += 1;
                    continue;
                }
                Err(()) => {
                    skips.unreadable += 1;
                    continue;
                }
            }
        } else {
            skips.other_scope += 1;
            continue;
        };
        iocs.push(Ioc {
            ip,
            feed_id: feed.id.clone(),
            confidence: DECISION_CONFIDENCE,
            threat_type: scenario_threat_type(&d.scenario),
            last_seen: now_ns,
            source_feed: feed.name.clone(),
        });
    }
    (iocs, skips)
}

/// The address an alert's source field holds, in the encoding alerts use.
fn alert_source(alert: &Alert) -> Option<IpAddr> {
    if alert.is_ipv6 {
        let mut bytes = [0u8; 16];
        for (i, word) in alert.src_addr.iter().enumerate() {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
        }
        Some(IpAddr::V6(bytes.into()))
    } else if alert.src_addr[0] == 0 {
        None
    } else {
        Some(IpAddr::V4(std::net::Ipv4Addr::from(alert.src_addr[0])))
    }
}

/// One source this agent blocked, aggregated over a reporting window.
///
/// This is everything a report carries about it: the address, which part of
/// the agent blocked it, how many times and between which two instants. No
/// destination, no port, no rule text and no payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    pub source: IpAddr,
    /// `ebpfsentinel/<component>`, e.g. `ebpfsentinel/ids`.
    pub scenario: String,
    pub count: u32,
    pub first_ns: u64,
    pub last_ns: u64,
}

/// Why an alert was not turned into a signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotASignal {
    /// The agent alerted without blocking.
    NotBlocked,
    /// An operator marked it a false positive.
    FalsePositive,
    /// The block came from an indicator: reporting it would hand somebody
    /// else's intelligence back as this host's own observation.
    FromIndicator,
    /// The source is missing or is a private, loopback or link-local address,
    /// which says nothing to anyone outside this network.
    NotPublic,
}

/// Collects the agent's blocks between two reports.
#[derive(Debug, Default)]
pub struct SignalBatch {
    pending: BTreeMap<(IpAddr, String), Signal>,
    dropped: u64,
}

impl SignalBatch {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `alert` is one of this agent's own blocks of a public source.
    pub fn qualifies(alert: &Alert) -> Result<IpAddr, NotASignal> {
        if alert.action != DomainMode::Block {
            return Err(NotASignal::NotBlocked);
        }
        if alert.false_positive {
            return Err(NotASignal::FalsePositive);
        }
        if alert.component == "threatintel" {
            return Err(NotASignal::FromIndicator);
        }
        match alert_source(alert) {
            Some(ip) if !FeedConfig::is_forbidden_ip(ip) => Ok(ip),
            _ => Err(NotASignal::NotPublic),
        }
    }

    /// Fold `alert` into the batch. Returns whether it was counted.
    pub fn observe(&mut self, alert: &Alert) -> bool {
        let Ok(source) = Self::qualifies(alert) else {
            return false;
        };
        let scenario = format!("{SCENARIO_PREFIX}/{}", alert.component);
        let key = (source, scenario);
        if let Some(signal) = self.pending.get_mut(&key) {
            signal.count = signal.count.saturating_add(1);
            signal.first_ns = signal.first_ns.min(alert.timestamp_ns);
            signal.last_ns = signal.last_ns.max(alert.timestamp_ns);
            return true;
        }
        if self.pending.len() >= MAX_PENDING_SIGNALS {
            self.dropped += 1;
            return false;
        }
        let scenario = key.1.clone();
        self.pending.insert(
            key,
            Signal {
                source,
                scenario,
                count: 1,
                first_ns: alert.timestamp_ns,
                last_ns: alert.timestamp_ns,
            },
        );
        true
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Take the window's signals and the number of sources that did not fit.
    pub fn drain(&mut self) -> (Vec<Signal>, u64) {
        let signals = std::mem::take(&mut self.pending).into_values().collect();
        (signals, std::mem::take(&mut self.dropped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threatintel::entity::FeedFormat;

    fn feed(max: usize) -> FeedConfig {
        FeedConfig {
            id: CROWDSEC_FEED_ID.to_string(),
            name: "CrowdSec".to_string(),
            url: "http://127.0.0.1:8080/v1/decisions".to_string(),
            format: FeedFormat::Crowdsec,
            enabled: true,
            refresh_interval_secs: 60,
            max_iocs: max,
            default_action: None,
            min_confidence: 0,
            field_mapping: None,
            auth_header: None,
        }
    }

    fn decision(scope: &str, value: &str, kind: &str, scenario: &str) -> Decision {
        Decision {
            scope: scope.to_string(),
            value: value.to_string(),
            kind: kind.to_string(),
            scenario: scenario.to_string(),
        }
    }

    fn alert(component: &str, action: DomainMode, src: u32) -> Alert {
        let mut alert: Alert = serde_json::from_value(serde_json::json!({
            "id": "a",
            "timestamp_ns": 10,
            "component": component,
            "severity": "High",
            "rule_id": "r",
            "action": "Alert",
            "src_addr": [src, 0, 0, 0],
            "dst_addr": [0x0a00_0001_u32, 0, 0, 0],
            "src_port": 4444,
            "dst_port": 22,
            "protocol": 6,
            "is_ipv6": false,
            "message": "m"
        }))
        .unwrap();
        alert.action = action;
        alert
    }

    const PUBLIC: u32 = 0xcb00_7101; // 203.0.113.1

    #[test]
    fn a_ban_on_one_address_is_an_indicator() {
        let (iocs, skips) = decisions_to_iocs(
            &[
                decision("Ip", "203.0.113.7", "ban", "crowdsecurity/ssh-bf"),
                decision(
                    "Range",
                    "2001:db8::1/128",
                    "ban",
                    "crowdsecurity/http-probing",
                ),
            ],
            &feed(10),
            5,
        );
        assert_eq!(skips.total(), 0);
        assert_eq!(iocs.len(), 2);
        assert_eq!(iocs[0].ip, "203.0.113.7".parse::<IpAddr>().unwrap());
        assert_eq!(iocs[0].confidence, DECISION_CONFIDENCE);
        assert_eq!(iocs[0].feed_id, CROWDSEC_FEED_ID);
        assert_eq!(iocs[0].last_seen, 5);
        assert_eq!(iocs[1].threat_type, ThreatType::Scanner);
    }

    #[test]
    fn what_is_not_loaded_is_counted_by_reason() {
        let (iocs, skips) = decisions_to_iocs(
            &[
                decision("Ip", "203.0.113.7", "captcha", "x"),
                decision("Range", "203.0.113.0/24", "ban", "x"),
                decision("Country", "FR", "ban", "x"),
                decision("Ip", "not-an-address", "ban", "x"),
                decision("Range", "203.0.113.0/40", "ban", "x"),
            ],
            &feed(10),
            0,
        );
        assert!(iocs.is_empty());
        assert_eq!(
            skips,
            DecisionSkips {
                not_ban: 1,
                ranges: 1,
                other_scope: 1,
                unreadable: 2,
            }
        );
        assert_eq!(skips.total(), 5);
    }

    #[test]
    fn the_list_is_cut_at_the_feed_limit() {
        let many: Vec<Decision> = (1..=5)
            .map(|i| decision("Ip", &format!("203.0.113.{i}"), "ban", "x"))
            .collect();
        let (iocs, _) = decisions_to_iocs(&many, &feed(3), 0);
        assert_eq!(iocs.len(), 3);
    }

    #[test]
    fn scenarios_map_onto_categories() {
        assert_eq!(
            scenario_threat_type("crowdsecurity/ssh-bf"),
            ThreatType::Other
        );
        assert_eq!(
            scenario_threat_type("crowdsecurity/http-crawl-non_statics"),
            ThreatType::Scanner
        );
        assert_eq!(
            scenario_threat_type("crowdsecurity/postfix-spam"),
            ThreatType::Spam
        );
        assert_eq!(
            scenario_threat_type("crowdsecurity/CVE-2021-44228"),
            ThreatType::Malware
        );
    }

    #[test]
    fn only_own_blocks_of_public_sources_are_signals() {
        assert!(SignalBatch::qualifies(&alert("ids", DomainMode::Block, PUBLIC)).is_ok());
        assert_eq!(
            SignalBatch::qualifies(&alert("ids", DomainMode::Alert, PUBLIC)),
            Err(NotASignal::NotBlocked)
        );
        assert_eq!(
            SignalBatch::qualifies(&alert("threatintel", DomainMode::Block, PUBLIC)),
            Err(NotASignal::FromIndicator)
        );
        assert_eq!(
            SignalBatch::qualifies(&alert("ids", DomainMode::Block, 0x0a00_0005)),
            Err(NotASignal::NotPublic)
        );
        let mut fp = alert("ids", DomainMode::Block, PUBLIC);
        fp.false_positive = true;
        assert_eq!(SignalBatch::qualifies(&fp), Err(NotASignal::FalsePositive));
    }

    #[test]
    fn repeated_blocks_fold_into_one_signal() {
        let mut batch = SignalBatch::new();
        let mut a = alert("ids", DomainMode::Block, PUBLIC);
        assert!(batch.observe(&a));
        a.timestamp_ns = 30;
        assert!(batch.observe(&a));
        a.timestamp_ns = 2;
        assert!(batch.observe(&a));
        assert!(batch.observe(&alert("ddos", DomainMode::Block, PUBLIC)));
        assert_eq!(batch.len(), 2);
        let (signals, dropped) = batch.drain();
        assert_eq!(dropped, 0);
        let ids = signals
            .iter()
            .find(|s| s.scenario == "ebpfsentinel/ids")
            .unwrap();
        assert_eq!(ids.count, 3);
        assert_eq!((ids.first_ns, ids.last_ns), (2, 30));
        assert_eq!(ids.source, "203.0.113.1".parse::<IpAddr>().unwrap());
        assert!(batch.is_empty());
    }

    #[test]
    fn a_full_batch_counts_what_it_drops() {
        let mut batch = SignalBatch::new();
        let base = 0xcb00_7100_u32;
        for i in 0..u32::try_from(MAX_PENDING_SIGNALS).unwrap() {
            let mut a = alert("ids", DomainMode::Block, base);
            a.src_addr[0] = 0x0800_0000 + i; // 8.0.0.0 onwards, public
            assert!(batch.observe(&a));
        }
        assert!(!batch.observe(&alert("ids", DomainMode::Block, base + 1)));
        let (signals, dropped) = batch.drain();
        assert_eq!(signals.len(), MAX_PENDING_SIGNALS);
        assert_eq!(dropped, 1);
    }
}

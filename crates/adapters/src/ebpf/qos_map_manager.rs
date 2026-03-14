use aya::Ebpf;
use aya::maps::{Array, HashMap, MapData};
use domain::common::error::DomainError;
use domain::qos::entity::{QosClassifier, QosPipe, QosQueue};
use ebpf_common::qos::{QosClassifierKey, QosClassifierValue, QosPipeConfig, QosQueueConfig};
use ports::secondary::qos_map_port::QosMapPort;
use tracing::info;

/// Manages `QoS` eBPF maps: `QOS_PIPE_CONFIG`, `QOS_QUEUE_CONFIG`, and `QOS_CLASSIFIERS`.
///
/// Provides typed wrappers around the raw eBPF maps for loading and
/// clearing `QoS` pipe, queue, and classifier configurations.
pub struct QosMapManager {
    pipe_config: Array<MapData, QosPipeConfig>,
    queue_config: Array<MapData, QosQueueConfig>,
    classifiers: HashMap<MapData, QosClassifierKey, QosClassifierValue>,
}

impl QosMapManager {
    /// Create a new `QosMapManager` by taking ownership of the `QoS` maps
    /// from the loaded eBPF program.
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
        let pipe_map = ebpf
            .take_map("QOS_PIPE_CONFIG")
            .ok_or_else(|| anyhow::anyhow!("map 'QOS_PIPE_CONFIG' not found in eBPF object"))?;
        let pipe_config = Array::try_from(pipe_map)?;
        info!("QOS_PIPE_CONFIG map acquired");

        let queue_map = ebpf
            .take_map("QOS_QUEUE_CONFIG")
            .ok_or_else(|| anyhow::anyhow!("map 'QOS_QUEUE_CONFIG' not found in eBPF object"))?;
        let queue_config = Array::try_from(queue_map)?;
        info!("QOS_QUEUE_CONFIG map acquired");

        let cls_map = ebpf
            .take_map("QOS_CLASSIFIERS")
            .ok_or_else(|| anyhow::anyhow!("map 'QOS_CLASSIFIERS' not found in eBPF object"))?;
        let classifiers = HashMap::try_from(cls_map)?;
        info!("QOS_CLASSIFIERS map acquired");

        Ok(Self {
            pipe_config,
            queue_config,
            classifiers,
        })
    }

    /// Convert a domain `QosPipe` to a `QosPipeConfig` eBPF struct.
    fn pipe_to_ebpf(pipe: &QosPipe, index: u8) -> QosPipeConfig {
        // Convert rate_bps to bytes_per_ns: (rate_bps / 8) / 1e9
        let bytes_per_ns = if pipe.rate_bps > 0 {
            pipe.rate_bps / 8 / 1_000_000_000
        } else {
            0
        };
        // Convert delay_ms to delay_ns
        let delay_ns = u64::from(pipe.delay_ms) * 1_000_000;
        // Convert loss_pct (0.0-100.0) to a fixed-point rate (0-10000)
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let loss_rate = if pipe.loss_pct > 0.0 {
            (pipe.loss_pct * 100.0) as u16 // 0.01% precision, max 10000
        } else {
            0u16
        };
        QosPipeConfig {
            bytes_per_ns,
            burst_bytes: pipe.burst_bytes,
            delay_ns,
            loss_rate,
            pipe_id: index,
            enabled: u8::from(pipe.enabled),
            group_mask: 0,
        }
    }

    /// Convert a domain `QosQueue` to a `QosQueueConfig` eBPF struct.
    fn queue_to_ebpf(queue: &QosQueue, pipe_index: u8) -> QosQueueConfig {
        QosQueueConfig {
            pipe_id: pipe_index,
            _padding1: 0,
            weight: queue.weight.min(100),
            enabled: u8::from(queue.enabled),
            _padding2: [0; 3],
        }
    }

    /// Convert a domain `QosClassifier` to key/value eBPF structs.
    fn classifier_to_ebpf(
        cls: &QosClassifier,
        queue_index: u8,
    ) -> (QosClassifierKey, QosClassifierValue) {
        let src_ip = cls
            .match_rule
            .src_ip
            .as_ref()
            .and_then(|s| parse_ip_to_u32(s))
            .unwrap_or(0);
        let dst_ip = cls
            .match_rule
            .dst_ip
            .as_ref()
            .and_then(|s| parse_ip_to_u32(s))
            .unwrap_or(0);

        let key = QosClassifierKey {
            src_ip,
            dst_ip,
            src_port: cls.match_rule.src_port,
            dst_port: cls.match_rule.dst_port,
            protocol: cls.match_rule.protocol,
            dscp: cls.match_rule.dscp,
            _padding: [0; 2],
        };
        let value = QosClassifierValue {
            queue_id: queue_index,
            #[allow(clippy::cast_possible_truncation)]
            priority: cls.priority.min(255) as u8,
            _padding: [0; 2],
            group_mask: 0,
        };
        (key, value)
    }

    /// Load pipe configurations into the eBPF array map.
    #[allow(clippy::cast_possible_truncation)]
    fn load_pipes_inner(&mut self, pipes: &[QosPipe]) -> Result<(), anyhow::Error> {
        for (i, pipe) in pipes.iter().enumerate() {
            let config = Self::pipe_to_ebpf(pipe, i as u8);
            self.pipe_config
                .set(i as u32, config, 0)
                .map_err(|e| anyhow::anyhow!("QOS_PIPE_CONFIG set at index {i} failed: {e}"))?;
        }
        info!(count = pipes.len(), "QoS pipes loaded into eBPF map");
        Ok(())
    }

    /// Load queue configurations into the eBPF array map.
    #[allow(clippy::cast_possible_truncation)]
    fn load_queues_inner(
        &mut self,
        queues: &[QosQueue],
        pipes: &[QosPipe],
    ) -> Result<(), anyhow::Error> {
        for (i, queue) in queues.iter().enumerate() {
            let pipe_index = pipes
                .iter()
                .position(|p| p.id == queue.pipe_id)
                .unwrap_or(0) as u8;
            let config = Self::queue_to_ebpf(queue, pipe_index);
            self.queue_config
                .set(i as u32, config, 0)
                .map_err(|e| anyhow::anyhow!("QOS_QUEUE_CONFIG set at index {i} failed: {e}"))?;
        }
        info!(count = queues.len(), "QoS queues loaded into eBPF map");
        Ok(())
    }

    /// Load classifier entries into the eBPF hash map.
    #[allow(clippy::cast_possible_truncation)]
    fn load_classifiers_inner(
        &mut self,
        classifiers: &[QosClassifier],
        queues: &[QosQueue],
    ) -> Result<(), anyhow::Error> {
        // Clear existing entries first
        let keys: Vec<QosClassifierKey> = self.classifiers.keys().filter_map(Result::ok).collect();
        for key in &keys {
            self.classifiers
                .remove(key)
                .map_err(|e| anyhow::anyhow!("QOS_CLASSIFIERS clear failed: {e}"))?;
        }

        for cls in classifiers {
            let queue_index = queues
                .iter()
                .position(|q| q.id == cls.queue_id)
                .unwrap_or(0) as u8;
            let (key, value) = Self::classifier_to_ebpf(cls, queue_index);
            self.classifiers
                .insert(key, value, 0)
                .map_err(|e| anyhow::anyhow!("QOS_CLASSIFIERS insert failed: {e}"))?;
        }
        info!(
            count = classifiers.len(),
            "QoS classifiers loaded into eBPF map"
        );
        Ok(())
    }

    /// Zero out pipe array entries.
    fn clear_pipes(&mut self, count: u32) {
        let zero = QosPipeConfig {
            bytes_per_ns: 0,
            burst_bytes: 0,
            delay_ns: 0,
            loss_rate: 0,
            pipe_id: 0,
            enabled: 0,
            group_mask: 0,
        };
        for i in 0..count {
            let _ = self.pipe_config.set(i, zero, 0);
        }
    }

    /// Zero out queue array entries.
    fn clear_queues(&mut self, count: u32) {
        let zero = QosQueueConfig {
            pipe_id: 0,
            _padding1: 0,
            weight: 0,
            enabled: 0,
            _padding2: [0; 3],
        };
        for i in 0..count {
            let _ = self.queue_config.set(i, zero, 0);
        }
    }

    /// Clear all classifier entries from the hash map.
    fn clear_classifiers(&mut self) -> Result<(), anyhow::Error> {
        let keys: Vec<QosClassifierKey> = self.classifiers.keys().filter_map(Result::ok).collect();
        for key in &keys {
            self.classifiers
                .remove(key)
                .map_err(|e| anyhow::anyhow!("QOS_CLASSIFIERS clear failed: {e}"))?;
        }
        Ok(())
    }

    /// Return the number of classifier entries in the map.
    pub fn classifier_count_raw(&self) -> usize {
        self.classifiers.keys().filter_map(Result::ok).count()
    }
}

impl QosMapPort for QosMapManager {
    fn load_pipes(&mut self, pipes: &[QosPipe]) -> Result<(), DomainError> {
        self.load_pipes_inner(pipes)
            .map_err(|e| DomainError::EngineError(format!("qos pipe map load failed: {e}")))
    }

    fn load_queues(&mut self, queues: &[QosQueue]) -> Result<(), DomainError> {
        // We need pipe info for pipe_id -> index mapping but we don't have it here.
        // The port trait only passes queues; we do best-effort index = 0 when pipe unknown.
        self.load_queues_inner(queues, &[])
            .map_err(|e| DomainError::EngineError(format!("qos queue map load failed: {e}")))
    }

    fn load_classifiers(&mut self, classifiers: &[QosClassifier]) -> Result<(), DomainError> {
        self.load_classifiers_inner(classifiers, &[])
            .map_err(|e| DomainError::EngineError(format!("qos classifier map load failed: {e}")))
    }

    fn clear_all(&mut self) -> Result<(), DomainError> {
        self.clear_pipes(ebpf_common::qos::MAX_QOS_PIPES);
        self.clear_queues(ebpf_common::qos::MAX_QOS_QUEUES);
        self.clear_classifiers().map_err(|e| {
            DomainError::EngineError(format!("qos classifier map clear failed: {e}"))
        })?;
        Ok(())
    }

    fn pipe_count(&self) -> Result<usize, DomainError> {
        // Array maps have a fixed size; we cannot know how many are "active"
        // without scanning. Return the max for now.
        Ok(ebpf_common::qos::MAX_QOS_PIPES as usize)
    }

    fn queue_count(&self) -> Result<usize, DomainError> {
        Ok(ebpf_common::qos::MAX_QOS_QUEUES as usize)
    }

    fn classifier_count(&self) -> Result<usize, DomainError> {
        Ok(self.classifier_count_raw())
    }
}

/// Parse an IP string (with optional CIDR suffix) to a big-endian `u32`.
/// Returns `None` on parse failure.
fn parse_ip_to_u32(s: &str) -> Option<u32> {
    let ip_str = s.split('/').next()?;
    let addr: std::net::Ipv4Addr = ip_str.parse().ok()?;
    Some(u32::from(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ip_to_u32_valid() {
        assert_eq!(parse_ip_to_u32("10.0.0.1"), Some(0x0A00_0001));
        assert_eq!(parse_ip_to_u32("192.168.1.0/24"), Some(0xC0A8_0100));
    }

    #[test]
    fn parse_ip_to_u32_invalid() {
        assert_eq!(parse_ip_to_u32("not-an-ip"), None);
        assert_eq!(parse_ip_to_u32(""), None);
    }

    #[test]
    fn pipe_to_ebpf_basic() {
        let pipe = QosPipe {
            id: "p-1".to_string(),
            rate_bps: 8_000_000_000, // 8 Gbps
            burst_bytes: 1_000_000,
            delay_ms: 0,
            loss_pct: 0.0,
            priority: 0,
            direction: domain::qos::entity::QosDirection::Egress,
            enabled: true,
            group_mask: 0,
        };
        let config = QosMapManager::pipe_to_ebpf(&pipe, 0);
        assert_eq!(config.pipe_id, 0);
        assert_eq!(config.enabled, 1);
        assert_eq!(config.burst_bytes, 1_000_000);
        // 8_000_000_000 / 8 / 1_000_000_000 = 1
        assert_eq!(config.bytes_per_ns, 1);
    }

    #[test]
    fn pipe_to_ebpf_zero_rate() {
        let pipe = QosPipe {
            id: "p-0".to_string(),
            rate_bps: 0,
            burst_bytes: 0,
            delay_ms: 0,
            loss_pct: 0.0,
            priority: 0,
            direction: domain::qos::entity::QosDirection::Egress,
            enabled: true,
            group_mask: 0,
        };
        let config = QosMapManager::pipe_to_ebpf(&pipe, 5);
        assert_eq!(config.bytes_per_ns, 0);
        assert_eq!(config.pipe_id, 5);
    }

    #[test]
    fn queue_to_ebpf_basic() {
        use domain::qos::entity::QosQueue;
        let queue = QosQueue {
            id: "q-1".to_string(),
            pipe_id: "p-1".to_string(),
            weight: 50,
            enabled: true,
        };
        let config = QosMapManager::queue_to_ebpf(&queue, 3);
        assert_eq!(config.pipe_id, 3);
        assert_eq!(config.weight, 50);
        assert_eq!(config.enabled, 1);
    }

    #[test]
    fn queue_to_ebpf_weight_clamped() {
        use domain::qos::entity::QosQueue;
        let queue = QosQueue {
            id: "q-2".to_string(),
            pipe_id: "p-1".to_string(),
            weight: 200,
            enabled: true,
        };
        let config = QosMapManager::queue_to_ebpf(&queue, 0);
        assert_eq!(config.weight, 100);
    }

    #[test]
    fn classifier_to_ebpf_wildcard() {
        use domain::qos::entity::{QosClassifier, QosDirection, QosMatchRule};
        let cls = QosClassifier {
            id: "c-1".to_string(),
            queue_id: "q-1".to_string(),
            direction: QosDirection::Egress,
            match_rule: QosMatchRule::default(),
            priority: 100,
            group_mask: 0,
        };
        let (key, value) = QosMapManager::classifier_to_ebpf(&cls, 2);
        assert_eq!(key.src_ip, 0);
        assert_eq!(key.dst_ip, 0);
        assert_eq!(key.src_port, 0);
        assert_eq!(key.dst_port, 0);
        assert_eq!(key.protocol, 0);
        assert_eq!(key.dscp, 0);
        assert_eq!(value.queue_id, 2);
        assert_eq!(value.priority, 100);
    }

    #[test]
    fn classifier_to_ebpf_with_match() {
        use domain::qos::entity::{QosClassifier, QosDirection, QosMatchRule};
        let cls = QosClassifier {
            id: "c-2".to_string(),
            queue_id: "q-1".to_string(),
            direction: QosDirection::Ingress,
            match_rule: QosMatchRule {
                src_ip: Some("10.0.0.0/8".to_string()),
                dst_ip: Some("192.168.1.1".to_string()),
                src_port: 1234,
                dst_port: 80,
                protocol: 6,
                dscp: 46,
                vlan_id: 0,
            },
            priority: 300,
            group_mask: 0,
        };
        let (key, value) = QosMapManager::classifier_to_ebpf(&cls, 0);
        assert_eq!(key.src_ip, 0x0A00_0000);
        assert_eq!(key.dst_ip, 0xC0A8_0101);
        assert_eq!(key.src_port, 1234);
        assert_eq!(key.dst_port, 80);
        assert_eq!(key.protocol, 6);
        assert_eq!(key.dscp, 46);
        assert_eq!(value.queue_id, 0);
        // priority clamped to u8
        assert_eq!(value.priority, 255);
    }
}

use crate::ebpf::feature_gates::{self, Feature};
use crate::ebpf::map_store::MapStore;
use aya::maps::{Array, HashMap, MapData};
use domain::common::error::DomainError;
use domain::qos::entity::{QosClassifier, QosDirection, QosPipe, QosQueue};
use ebpf_common::qos::{
    QOS_DIR_BOTH, QOS_DIR_EGRESS, QOS_DIR_INGRESS, QOS_SCOPE_STRIDE, QOS_SHAPE_NO_DSCP,
    QOS_SHAPES_ALL_EMPTY, QosClassifierKey, QosClassifierValue, QosPipeConfig, QosQueueConfig,
    VLAN_ANY, qos_shape_of,
};
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
    /// Which classifier shapes the shaper may skip.
    ///
    /// Optional because only `tc-qos` declares it: a build or a deployment
    /// where the map is absent publishes nothing, the program reads zero and
    /// its ladder walks every step, which is what it did before this existed.
    empty_shapes: Option<Array<MapData, u32>>,
}

impl QosMapManager {
    /// Create a new `QosMapManager` by taking ownership of the `QoS` maps
    /// from the loaded eBPF program.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
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

        let empty_shapes = ebpf
            .take_map("QOS_EMPTY_SHAPES")
            .and_then(|map| Array::try_from(map).ok());
        if empty_shapes.is_some() {
            info!("QOS_EMPTY_SHAPES map acquired");
        }

        // The map is pinned, so it survives a restart: the answer has to be
        // counted rather than assumed. An empty set closes the shaper's whole
        // classification ladder, which is the widest lookup in the chain, and
        // the shapes below cut what is left of it when the set is not empty.
        feature_gates::publish(Feature::QosClassifiers, classifiers.keys().next().is_none());

        let mask = shapes_mask(classifiers.keys().filter_map(Result::ok));

        let mut manager = Self {
            pipe_config,
            queue_config,
            classifiers,
            empty_shapes,
        };
        manager.publish_shapes(mask);

        Ok(manager)
    }

    /// Write the shape mask where the shaper reads it.
    ///
    /// Failure costs lookups rather than rules, in either direction: the
    /// program reads whatever was last written, and every value it can read is
    /// a value that walks at least the steps the table needs.
    fn publish_shapes(&mut self, mask: u32) {
        if let Some(shapes) = self.empty_shapes.as_mut()
            && let Err(e) = shapes.set(0, mask, 0)
        {
            info!(error = %e, "QOS_EMPTY_SHAPES publish failed, shaper walks every shape");
        }
    }

    /// Convert a domain `QosPipe` to a `QosPipeConfig` eBPF struct.
    fn pipe_to_ebpf(pipe: &QosPipe, index: u8) -> QosPipeConfig {
        // Convert rate (bits/sec) to nanoseconds-per-byte: 1e9 / (rate_bps / 8)
        // = 8e9 / rate_bps. Integer math stays nonzero for any rate up to 8 Gbps
        // (e.g. 10 Mbps → 800 ns/byte); 0 means unlimited.
        let ns_per_byte = 8_000_000_000u64.checked_div(pipe.rate_bps).unwrap_or(0);
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
            ns_per_byte,
            burst_bytes: pipe.burst_bytes,
            delay_ns,
            loss_rate,
            pipe_id: index,
            enabled: u8::from(pipe.enabled),
            group_mask: pipe.group_mask,
            tenant_id: pipe.tenant_id,
            direction: direction_to_ebpf(pipe.direction),
            _pad: [0; 3],
        }
    }

    /// Convert a domain `QosQueue` to a `QosQueueConfig` eBPF struct.
    fn queue_to_ebpf(queue: &QosQueue, pipe_index: u8) -> QosQueueConfig {
        QosQueueConfig {
            pipe_id: pipe_index,
            enabled: u8::from(queue.enabled),
            _padding: [0; 2],
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
            vlan_id: cls.match_rule.vlan_id.unwrap_or(VLAN_ANY),
        };
        let value = QosClassifierValue {
            queue_id: queue_index,
            _padding: [0; 3],
            group_mask: cls.group_mask,
            tenant_id: cls.tenant_id,
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
        // Open the ladder before the first insert, so a rule is never loaded
        // behind a gate still saying the table is empty. A load that fails
        // half way leaves it open, which costs lookups and never a rule. The
        // shape mask is opened the same way and for the same reason.
        feature_gates::publish(Feature::QosClassifiers, false);
        self.publish_shapes(0);

        // Clear existing entries first
        let keys: Vec<QosClassifierKey> = self.classifiers.keys().filter_map(Result::ok).collect();
        for key in &keys {
            self.classifiers
                .remove(key)
                .map_err(|e| anyhow::anyhow!("QOS_CLASSIFIERS clear failed: {e}"))?;
        }

        let mut loaded = 0usize;
        let mut written: Vec<QosClassifierKey> = Vec::new();
        for index in winning_classifier_indices(classifiers, queues) {
            let cls = &classifiers[index];
            let queue_index = queues
                .iter()
                .position(|q| q.id == cls.queue_id)
                .unwrap_or(0) as u8;
            let (key, value) = Self::classifier_to_ebpf(cls, queue_index);
            self.classifiers
                .insert(key, value, 0)
                .map_err(|e| anyhow::anyhow!("QOS_CLASSIFIERS insert failed: {e}"))?;
            written.push(key);
            loaded += 1;
        }
        // A rule set can win nothing - every classifier pointing at a queue
        // that does not exist - so the gate follows what was actually written
        // rather than what was handed in.
        feature_gates::publish(Feature::QosClassifiers, loaded == 0);
        // Same rule for the shapes: what was written rather than what was
        // handed in, since the two differ whenever a key collapsed onto
        // another or a rule lost the tie on priority.
        let mask = shapes_mask(written.into_iter());
        self.publish_shapes(mask);
        info!(
            count = classifiers.len(),
            "QoS classifiers loaded into eBPF map"
        );
        Ok(())
    }

    /// Zero out pipe array entries.
    fn clear_pipes(&mut self, count: u32) {
        let zero = QosPipeConfig {
            ns_per_byte: 0,
            burst_bytes: 0,
            delay_ns: 0,
            loss_rate: 0,
            pipe_id: 0,
            enabled: 0,
            group_mask: 0,
            tenant_id: 0,
            direction: QOS_DIR_EGRESS,
            _pad: [0; 3],
        };
        for i in 0..count {
            let _ = self.pipe_config.set(i, zero, 0);
        }
    }

    /// Zero out queue array entries.
    fn clear_queues(&mut self, count: u32) {
        let zero = QosQueueConfig {
            pipe_id: 0,
            enabled: 0,
            _padding: [0; 2],
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
        feature_gates::publish(Feature::QosClassifiers, true);
        self.publish_shapes(QOS_SHAPES_ALL_EMPTY);
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

/// Which classifier shapes hold no rule, from the keys actually in the map.
///
/// The shaper's ladder probes one key shape per step and has no way of knowing
/// which of them a rule was ever written in, so it walks all of them. This is
/// the answer, in the inverted sense the data plane reads: a set bit is a shape
/// holding nothing, and zero is the safe value because it walks everything.
///
/// A key [`qos_shape_of`] does not recognise collapses the whole mask to zero.
/// Such a key is one no step of the ladder ever builds, so the rule is already
/// unreachable, and a mask claiming its shape is empty would be a true
/// statement about a shape and a misleading one about the rule. Publishing
/// nothing leaves the ladder exactly as it was.
fn shapes_mask(keys: impl Iterator<Item = QosClassifierKey>) -> u32 {
    let mut mask = QOS_SHAPES_ALL_EMPTY;
    for key in keys {
        let Some(shape) = qos_shape_of(
            key.src_ip,
            key.dst_ip,
            key.src_port,
            key.dst_port,
            key.protocol,
            key.dscp,
        ) else {
            return 0;
        };
        let scope_shift = if key.vlan_id == VLAN_ANY {
            QOS_SCOPE_STRIDE
        } else {
            0
        };
        mask &= !(1u32 << (shape + scope_shift));
        if key.dscp != 0 {
            mask &= !(1u32 << (QOS_SHAPE_NO_DSCP + scope_shift));
        }
    }
    mask
}

/// Pick which classifiers actually reach the eBPF map, in load order.
///
/// Several classifiers can collapse onto the same key: the map is keyed by the
/// match tuple, and a wildcard is encoded as a zero in that tuple rather than
/// stored beside it, so two rules that differ only in what they leave open are
/// indistinguishable to the kernel lookup. Nothing in the data plane can
/// arbitrate between them, so the tie is settled here by the documented meaning
/// of `priority` - lower is matched first. Ties on priority keep the earlier
/// rule, which is the order the configuration file lists them in.
fn winning_classifier_indices(classifiers: &[QosClassifier], queues: &[QosQueue]) -> Vec<usize> {
    let mut winner_by_key: std::collections::HashMap<QosClassifierKey, usize> =
        std::collections::HashMap::new();
    let mut order: Vec<usize> = Vec::new();

    for (index, cls) in classifiers.iter().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let queue_index = queues
            .iter()
            .position(|q| q.id == cls.queue_id)
            .unwrap_or(0) as u8;
        let (key, _) = QosMapManager::classifier_to_ebpf(cls, queue_index);

        match winner_by_key.get(&key).copied() {
            Some(current) if classifiers[current].priority <= cls.priority => {}
            Some(current) => {
                order.retain(|&i| i != current);
                order.push(index);
                winner_by_key.insert(key, index);
            }
            None => {
                order.push(index);
                winner_by_key.insert(key, index);
            }
        }
    }

    order.sort_unstable();
    order
}

/// Encode a domain direction for the eBPF pipe config.
///
/// The program runs on both TC hooks and reads this byte to decide whether
/// the pipe applies to the packet in front of it.
fn direction_to_ebpf(direction: QosDirection) -> u8 {
    match direction {
        QosDirection::Ingress => QOS_DIR_INGRESS,
        QosDirection::Egress => QOS_DIR_EGRESS,
        QosDirection::Both => QOS_DIR_BOTH,
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
    use ebpf_common::qos::{
        QOS_SCOPE_SHAPES_EMPTY, QOS_SHAPE_CATCHALL, QOS_SHAPE_DPORT, QOS_SHAPE_DSCP,
        QOS_SHAPE_FULL, qos_shape_bit_any, qos_shape_bit_vlan,
    };

    fn key(
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        dscp: u8,
        vlan_id: u16,
    ) -> QosClassifierKey {
        QosClassifierKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            dscp,
            vlan_id,
        }
    }

    #[test]
    fn an_empty_table_closes_every_shape() {
        assert_eq!(shapes_mask(std::iter::empty()), QOS_SHAPES_ALL_EMPTY);
    }

    #[test]
    fn a_rule_opens_its_own_shape_and_nothing_else() {
        let mask = shapes_mask([key(0, 0, 0, 443, 6, 0, VLAN_ANY)].into_iter());

        // The shape it was written in, in the scope it belongs to.
        assert_eq!(mask & qos_shape_bit_any(QOS_SHAPE_DPORT), 0);
        // The same shape in the other scope stays closed.
        assert_ne!(mask & qos_shape_bit_vlan(QOS_SHAPE_DPORT), 0);
        // And so does every other shape of its own scope.
        assert_ne!(mask & qos_shape_bit_any(QOS_SHAPE_FULL), 0);
        assert_ne!(mask & qos_shape_bit_any(QOS_SHAPE_CATCHALL), 0);
        // It names no marking, so the first pass of the ladder stays cut.
        assert_ne!(mask & qos_shape_bit_any(QOS_SHAPE_NO_DSCP), 0);
    }

    #[test]
    fn a_rule_naming_a_marking_opens_the_first_pass_of_its_scope() {
        let mask = shapes_mask([key(0, 0, 0, 0, 0, 46, 10)].into_iter());

        assert_eq!(mask & qos_shape_bit_vlan(QOS_SHAPE_DSCP), 0);
        assert_eq!(mask & qos_shape_bit_vlan(QOS_SHAPE_NO_DSCP), 0);
        // The VLAN-agnostic scope heard nothing about a marking.
        assert_ne!(mask & qos_shape_bit_any(QOS_SHAPE_NO_DSCP), 0);
    }

    #[test]
    fn a_rule_naming_a_vlan_lands_in_the_vlan_scope() {
        let mask = shapes_mask([key(0, 0, 0, 0, 0, 0, 0)].into_iter());

        // VLAN 0 is a VLAN: only VLAN_ANY means the other scope.
        assert_eq!(mask & qos_shape_bit_vlan(QOS_SHAPE_CATCHALL), 0);
        assert_ne!(mask & qos_shape_bit_any(QOS_SHAPE_CATCHALL), 0);
    }

    #[test]
    fn a_key_the_ladder_never_builds_opens_everything() {
        // A rule naming a source host and no destination host: every step of
        // the ladder carrying a host carries both, so the key is unreachable
        // and the mask says nothing rather than closing a shape around it.
        let mask = shapes_mask(
            [
                key(0x0A00_0001, 0, 0, 0, 6, 0, VLAN_ANY),
                key(0, 0, 0, 443, 6, 0, VLAN_ANY),
            ]
            .into_iter(),
        );

        assert_eq!(mask, 0);
    }

    #[test]
    fn a_scope_nothing_was_written_in_is_closed_whole() {
        let mask = shapes_mask([key(0, 0, 0, 443, 6, 0, 10)].into_iter());

        let any = (mask >> QOS_SCOPE_STRIDE) & QOS_SCOPE_SHAPES_EMPTY;
        assert_eq!(any, QOS_SCOPE_SHAPES_EMPTY);
        let in_vlan = mask & QOS_SCOPE_SHAPES_EMPTY;
        assert_ne!(in_vlan, QOS_SCOPE_SHAPES_EMPTY);
    }

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
            direction: domain::qos::entity::QosDirection::Egress,
            enabled: true,
            group_mask: 0,
            tenant_id: 0,
        };
        let config = QosMapManager::pipe_to_ebpf(&pipe, 0);
        assert_eq!(config.pipe_id, 0);
        assert_eq!(config.enabled, 1);
        assert_eq!(config.burst_bytes, 1_000_000);
        // 8_000_000_000 / 8_000_000_000 = 1 ns per byte
        assert_eq!(config.ns_per_byte, 1);
    }

    #[test]
    fn pipe_to_ebpf_zero_rate() {
        let pipe = QosPipe {
            id: "p-0".to_string(),
            rate_bps: 0,
            burst_bytes: 0,
            delay_ms: 0,
            loss_pct: 0.0,
            direction: domain::qos::entity::QosDirection::Egress,
            enabled: true,
            group_mask: 0,
            tenant_id: 0,
        };
        let config = QosMapManager::pipe_to_ebpf(&pipe, 5);
        assert_eq!(config.ns_per_byte, 0);
        assert_eq!(config.pipe_id, 5);
    }

    #[test]
    fn pipe_to_ebpf_carries_the_configured_tenant() {
        let pipe = QosPipe {
            id: "p-tenant".to_string(),
            rate_bps: 1_000_000,
            burst_bytes: 64_000,
            delay_ms: 0,
            loss_pct: 0.0,
            direction: QosDirection::Egress,
            enabled: true,
            group_mask: 0,
            tenant_id: 4,
        };
        assert_eq!(QosMapManager::pipe_to_ebpf(&pipe, 0).tenant_id, 4);
    }

    #[test]
    fn pipe_to_ebpf_carries_the_configured_direction() {
        for (direction, expected) in [
            (QosDirection::Egress, QOS_DIR_EGRESS),
            (QosDirection::Ingress, QOS_DIR_INGRESS),
            (QosDirection::Both, QOS_DIR_BOTH),
        ] {
            let pipe = QosPipe {
                id: "p-dir".to_string(),
                rate_bps: 1_000_000,
                burst_bytes: 64_000,
                delay_ms: 0,
                loss_pct: 0.0,
                direction,
                enabled: true,
                group_mask: 0,
                tenant_id: 0,
            };
            let config = QosMapManager::pipe_to_ebpf(&pipe, 1);
            assert_eq!(config.direction, expected, "direction {direction}");
        }
    }

    #[test]
    fn queue_to_ebpf_basic() {
        use domain::qos::entity::QosQueue;
        let queue = QosQueue {
            id: "q-1".to_string(),
            pipe_id: "p-1".to_string(),
            enabled: true,
        };
        let config = QosMapManager::queue_to_ebpf(&queue, 3);
        assert_eq!(config.pipe_id, 3);
        assert_eq!(config.enabled, 1);
    }

    #[test]
    fn a_disabled_queue_reaches_the_map_disabled() {
        use domain::qos::entity::QosQueue;
        let queue = QosQueue {
            id: "q-2".to_string(),
            pipe_id: "p-1".to_string(),
            enabled: false,
        };
        let config = QosMapManager::queue_to_ebpf(&queue, 0);
        assert_eq!(config.enabled, 0);
    }

    #[test]
    fn classifier_to_ebpf_wildcard() {
        use domain::qos::entity::{QosClassifier, QosMatchRule};
        let cls = QosClassifier {
            id: "c-1".to_string(),
            queue_id: "q-1".to_string(),
            match_rule: QosMatchRule::default(),
            priority: 100,
            group_mask: 0,
            tenant_id: 0,
        };
        let (key, value) = QosMapManager::classifier_to_ebpf(&cls, 2);
        assert_eq!(key.src_ip, 0);
        assert_eq!(key.dst_ip, 0);
        assert_eq!(key.src_port, 0);
        assert_eq!(key.dst_port, 0);
        assert_eq!(key.protocol, 0);
        assert_eq!(key.dscp, 0);
        assert_eq!(key.vlan_id, VLAN_ANY);
        assert_eq!(value.queue_id, 2);
    }

    #[test]
    fn classifier_to_ebpf_carries_the_configured_tenant() {
        use domain::qos::entity::{QosClassifier, QosMatchRule};
        let cls = QosClassifier {
            id: "c-tenant".to_string(),
            queue_id: "q-1".to_string(),
            match_rule: QosMatchRule::default(),
            priority: 100,
            group_mask: 0,
            tenant_id: 4,
        };
        let (_, value) = QosMapManager::classifier_to_ebpf(&cls, 0);
        assert_eq!(value.tenant_id, 4);
    }

    #[test]
    fn classifier_to_ebpf_with_match() {
        use domain::qos::entity::{QosClassifier, QosMatchRule};
        let cls = QosClassifier {
            id: "c-2".to_string(),
            queue_id: "q-1".to_string(),
            match_rule: QosMatchRule {
                src_ip: Some("10.0.0.0/8".to_string()),
                dst_ip: Some("192.168.1.1".to_string()),
                src_port: 1234,
                dst_port: 80,
                protocol: 6,
                dscp: 46,
                vlan_id: Some(0),
            },
            priority: 300,
            group_mask: 0,
            tenant_id: 0,
        };
        let (key, value) = QosMapManager::classifier_to_ebpf(&cls, 0);
        assert_eq!(key.src_ip, 0x0A00_0000);
        assert_eq!(key.dst_ip, 0xC0A8_0101);
        assert_eq!(key.src_port, 1234);
        assert_eq!(key.dst_port, 80);
        assert_eq!(key.protocol, 6);
        assert_eq!(key.dscp, 46);
        // Some(0) is untagged-only, not the wildcard.
        assert_eq!(key.vlan_id, 0);
        assert_eq!(value.queue_id, 0);
    }

    fn classifier_on_port(id: &str, queue_id: &str, dst_port: u16, priority: u32) -> QosClassifier {
        use domain::qos::entity::QosMatchRule;
        QosClassifier {
            id: id.to_string(),
            queue_id: queue_id.to_string(),
            match_rule: QosMatchRule {
                dst_port,
                ..QosMatchRule::default()
            },
            priority,
            group_mask: 0,
            tenant_id: 0,
        }
    }

    fn queue(id: &str) -> QosQueue {
        QosQueue {
            id: id.to_string(),
            pipe_id: "p-1".to_string(),
            enabled: true,
        }
    }

    #[test]
    fn classifiers_on_distinct_keys_are_all_written() {
        let queues = vec![queue("q-1")];
        let classifiers = vec![
            classifier_on_port("c-1", "q-1", 80, 100),
            classifier_on_port("c-2", "q-1", 443, 100),
        ];
        assert_eq!(
            winning_classifier_indices(&classifiers, &queues),
            vec![0, 1]
        );
    }

    #[test]
    fn the_lowest_priority_number_wins_a_shared_key() {
        let queues = vec![queue("q-1"), queue("q-2")];
        let classifiers = vec![
            classifier_on_port("c-loser", "q-1", 5201, 200),
            classifier_on_port("c-winner", "q-2", 5201, 10),
        ];
        assert_eq!(winning_classifier_indices(&classifiers, &queues), vec![1]);
    }

    #[test]
    fn a_shared_key_keeps_the_first_rule_when_priorities_tie() {
        let queues = vec![queue("q-1"), queue("q-2")];
        let classifiers = vec![
            classifier_on_port("c-first", "q-1", 5201, 100),
            classifier_on_port("c-second", "q-2", 5201, 100),
        ];
        assert_eq!(winning_classifier_indices(&classifiers, &queues), vec![0]);
    }

    #[test]
    fn a_later_rule_does_not_reclaim_a_key_it_already_lost() {
        let queues = vec![queue("q-1")];
        let classifiers = vec![
            classifier_on_port("c-mid", "q-1", 5201, 50),
            classifier_on_port("c-best", "q-1", 5201, 10),
            classifier_on_port("c-worst", "q-1", 5201, 900),
        ];
        assert_eq!(winning_classifier_indices(&classifiers, &queues), vec![1]);
    }
}

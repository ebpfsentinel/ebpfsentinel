use crate::secondary::metrics_port::{
    AlertMetrics, AuditMetrics, ConfigMetrics, ConntrackMetrics, DdosMetrics, DlpMetrics,
    DnsMetrics, DomainMetrics, EventMetrics, FirewallMetrics, IpsMetrics, LbMetrics, PacketMetrics,
    RoutingMetrics, SystemMetrics,
};

/// No-op implementation of all metrics sub-traits for use in tests.
///
/// All methods inherit the default no-op implementations from the sub-traits.
pub struct NoopMetrics;

impl PacketMetrics for NoopMetrics {}
impl FirewallMetrics for NoopMetrics {}
impl AlertMetrics for NoopMetrics {}
impl IpsMetrics for NoopMetrics {}
impl DnsMetrics for NoopMetrics {}
impl DomainMetrics for NoopMetrics {}
impl SystemMetrics for NoopMetrics {}
impl ConfigMetrics for NoopMetrics {}
impl EventMetrics for NoopMetrics {}
impl DlpMetrics for NoopMetrics {}
impl DdosMetrics for NoopMetrics {}
impl ConntrackMetrics for NoopMetrics {}
impl RoutingMetrics for NoopMetrics {}
impl AuditMetrics for NoopMetrics {}
impl LbMetrics for NoopMetrics {}

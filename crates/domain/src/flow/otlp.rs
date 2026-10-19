//! The one mapping from a flow record to the attributes of an OTLP log.
//!
//! A format is a contract, so the field list is written here once and
//! asserted by a test rather than read off a collector's screen. Three rules
//! decide every name below:
//!
//! - **A semantic convention is used where one exists.** The five-tuple, the
//!   address family, the process and the container and pod names all have
//!   settled names in the OpenTelemetry conventions, so a SIEM already
//!   holding OTLP logs from anything else queries ours with the same field.
//! - **Everything else is namespaced under `ebpfsentinel.`**, because the
//!   conventions describe a request and a span and have nothing to say about
//!   a flow's packet and byte deltas, its end reason or a systemd unit. An
//!   invented `flow.bytes` would collide with the day the conventions define
//!   one and mean something else.
//! - **Absence is absence.** A field the node could not read has no
//!   attribute at all: no empty string, no zero. A transited flow carries no
//!   workload attribute rather than attributes saying nothing, which is the
//!   same decision the IPFIX templates make structurally.
//!
//! The order is the order of the pushes below and is deliberately fixed: two
//! runs over the same readings must produce the same record.

use crate::flow::entity::FlowRecord;
use crate::workload::entity::Workload;

/// The event name every flow log carries, which is what tells a collector
/// holding alerts and flows from the same agent which of the two it has.
pub const EVENT_NAME: &str = "ebpfsentinel.flow";

/// Semantic-convention names, in the spelling the conventions give them.
pub const SOURCE_ADDRESS: &str = "source.address";
pub const SOURCE_PORT: &str = "source.port";
pub const DESTINATION_ADDRESS: &str = "destination.address";
pub const DESTINATION_PORT: &str = "destination.port";
pub const NETWORK_TRANSPORT: &str = "network.transport";
pub const NETWORK_TYPE: &str = "network.type";
pub const PROCESS_PID: &str = "process.pid";
pub const PROCESS_EXECUTABLE_PATH: &str = "process.executable.path";
pub const CONTAINER_ID: &str = "container.id";
pub const CONTAINER_IMAGE_NAME: &str = "container.image.name";
pub const K8S_POD_NAME: &str = "k8s.pod.name";
pub const K8S_NAMESPACE_NAME: &str = "k8s.namespace.name";

/// What the conventions do not name, under this project's own prefix.
pub const FLOW_PROTOCOL_NUMBER: &str = "ebpfsentinel.flow.protocol_number";
pub const FLOW_PACKETS: &str = "ebpfsentinel.flow.packets";
pub const FLOW_BYTES: &str = "ebpfsentinel.flow.bytes";
pub const FLOW_PACKETS_REVERSE: &str = "ebpfsentinel.flow.packets_reverse";
pub const FLOW_BYTES_REVERSE: &str = "ebpfsentinel.flow.bytes_reverse";
pub const FLOW_START_TIME: &str = "ebpfsentinel.flow.start_time_unix_ms";
pub const FLOW_END_TIME: &str = "ebpfsentinel.flow.end_time_unix_ms";
pub const FLOW_DURATION_MS: &str = "ebpfsentinel.flow.duration_ms";
pub const FLOW_END_REASON: &str = "ebpfsentinel.flow.end_reason";
pub const FLOW_END_REASON_CODE: &str = "ebpfsentinel.flow.end_reason_code";
pub const FLOW_SAMPLING: &str = "ebpfsentinel.flow.sampling";
pub const WORKLOAD_SOURCE: &str = "ebpfsentinel.workload.source";
pub const WORKLOAD_UID: &str = "ebpfsentinel.workload.uid";
pub const WORKLOAD_CGROUP_ID: &str = "ebpfsentinel.workload.cgroup_id";
pub const WORKLOAD_UNIT: &str = "ebpfsentinel.workload.unit";
pub const WORKLOAD_SERVICE_ACCOUNT: &str = "ebpfsentinel.workload.service_account";

/// The attributes of one flow record, in the order they are written.
///
/// `network.transport` is only written for a protocol the conventions have a
/// word for, which is why the protocol number is always written beside it: an
/// ESP or a GRE flow would otherwise reach a collector with its protocol
/// nowhere in the record.
#[must_use]
pub fn attributes(record: &FlowRecord) -> Vec<(&'static str, String)> {
    let mut attributes = Vec::with_capacity(24);

    attributes.push((SOURCE_ADDRESS, record.src.to_string()));
    attributes.push((SOURCE_PORT, record.src_port.to_string()));
    attributes.push((DESTINATION_ADDRESS, record.dst.to_string()));
    attributes.push((DESTINATION_PORT, record.dst_port.to_string()));
    if let Some(transport) = conventional_transport(record.protocol) {
        attributes.push((NETWORK_TRANSPORT, transport.to_string()));
    }
    attributes.push((FLOW_PROTOCOL_NUMBER, record.protocol.to_string()));
    attributes.push((
        NETWORK_TYPE,
        if record.is_ipv6() { "ipv6" } else { "ipv4" }.to_string(),
    ));

    attributes.push((FLOW_PACKETS, record.packets.to_string()));
    attributes.push((FLOW_BYTES, record.bytes.to_string()));
    attributes.push((FLOW_PACKETS_REVERSE, record.packets_rev.to_string()));
    attributes.push((FLOW_BYTES_REVERSE, record.bytes_rev.to_string()));

    attributes.push((FLOW_START_TIME, record.start_ms.to_string()));
    attributes.push((FLOW_END_TIME, record.end_ms.to_string()));
    attributes.push((
        FLOW_DURATION_MS,
        record.end_ms.saturating_sub(record.start_ms).to_string(),
    ));
    attributes.push((FLOW_END_REASON, record.reason.as_str().to_string()));
    attributes.push((FLOW_END_REASON_CODE, record.reason.code().to_string()));

    if let Some(workload) = record.workload.as_ref() {
        push_workload(&mut attributes, workload);
    }

    attributes
}

/// The one-line body a reader sees in the message column of a SIEM, which is
/// the five-tuple and nothing a query should be written against: every field
/// worth filtering on is an attribute.
#[must_use]
pub fn summary(record: &FlowRecord) -> String {
    format!(
        "{} {}:{} -> {}:{} {} packets {} bytes",
        record.protocol_name(),
        record.src,
        record.src_port,
        record.dst,
        record.dst_port,
        record.packets,
        record.bytes
    )
}

/// The transport word the conventions define, or `None` for a protocol they
/// say nothing about.
fn conventional_transport(protocol: u8) -> Option<&'static str> {
    match protocol {
        6 => Some("tcp"),
        17 => Some("udp"),
        _ => None,
    }
}

/// The workload block, which is present only where the node resolved one.
fn push_workload(attributes: &mut Vec<(&'static str, String)>, workload: &Workload) {
    attributes.push((PROCESS_PID, workload.pid.to_string()));
    attributes.push((WORKLOAD_SOURCE, workload.source.as_str().to_string()));
    push_text(attributes, PROCESS_EXECUTABLE_PATH, workload.exe.as_deref());
    if let Some(uid) = workload.uid {
        attributes.push((WORKLOAD_UID, uid.to_string()));
    }
    if let Some(cgroup) = workload.cgroup {
        attributes.push((WORKLOAD_CGROUP_ID, cgroup.to_string()));
    }
    push_text(attributes, CONTAINER_ID, workload.container.as_deref());
    push_text(attributes, CONTAINER_IMAGE_NAME, workload.image.as_deref());
    push_text(attributes, K8S_POD_NAME, workload.pod.as_deref());
    push_text(
        attributes,
        K8S_NAMESPACE_NAME,
        workload.namespace.as_deref(),
    );
    push_text(
        attributes,
        WORKLOAD_SERVICE_ACCOUNT,
        workload.service_account.as_deref(),
    );
    push_text(attributes, WORKLOAD_UNIT, workload.unit.as_deref());
}

/// Write a text attribute, skipping both absence and the empty string: a
/// field holding `""` is one a query matches and learns nothing from.
fn push_text(attributes: &mut Vec<(&'static str, String)>, key: &'static str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        attributes.push((key, value.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::flow::entity::FlowEndReason;
    use crate::workload::entity::WorkloadSource;

    fn record() -> FlowRecord {
        FlowRecord {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            dst: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            src_port: 51_234,
            dst_port: 443,
            protocol: 6,
            packets: 12,
            bytes: 2_048,
            packets_rev: 9,
            bytes_rev: 8_192,
            start_ms: 1_760_000_000_000,
            end_ms: 1_760_000_012_500,
            reason: FlowEndReason::IdleTimeout,
            workload: None,
        }
    }

    fn workload() -> Workload {
        Workload {
            pid: 4_242,
            source: WorkloadSource::Socket,
            exe: Some("/usr/bin/curl".to_string()),
            uid: Some(1_000),
            cgroup: Some(78_912),
            container: Some("c0ffee".to_string()),
            image: Some("docker.io/library/nginx:1.27".to_string()),
            pod: Some("web-7f9".to_string()),
            namespace: Some("shop".to_string()),
            service_account: Some("web".to_string()),
            unit: Some("nginx.service".to_string()),
        }
    }

    fn value<'a>(attributes: &'a [(&'static str, String)], key: &str) -> Option<&'a str> {
        attributes
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn a_transited_flow_carries_the_five_tuple_and_no_workload() {
        let attributes = attributes(&record());
        let names: Vec<&str> = attributes.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            vec![
                SOURCE_ADDRESS,
                SOURCE_PORT,
                DESTINATION_ADDRESS,
                DESTINATION_PORT,
                NETWORK_TRANSPORT,
                FLOW_PROTOCOL_NUMBER,
                NETWORK_TYPE,
                FLOW_PACKETS,
                FLOW_BYTES,
                FLOW_PACKETS_REVERSE,
                FLOW_BYTES_REVERSE,
                FLOW_START_TIME,
                FLOW_END_TIME,
                FLOW_DURATION_MS,
                FLOW_END_REASON,
                FLOW_END_REASON_CODE,
            ],
            "the field list of a flow with no local process is this and nothing else"
        );
        assert_eq!(value(&attributes, SOURCE_ADDRESS), Some("10.0.0.7"));
        assert_eq!(value(&attributes, DESTINATION_PORT), Some("443"));
        assert_eq!(value(&attributes, NETWORK_TRANSPORT), Some("tcp"));
        assert_eq!(value(&attributes, NETWORK_TYPE), Some("ipv4"));
        assert_eq!(value(&attributes, FLOW_DURATION_MS), Some("12500"));
        assert_eq!(value(&attributes, FLOW_END_REASON), Some("idle_timeout"));
        assert_eq!(value(&attributes, FLOW_END_REASON_CODE), Some("1"));
    }

    #[test]
    fn a_resolved_workload_adds_its_own_block_and_nothing_else() {
        let full = FlowRecord {
            workload: Some(workload()),
            ..record()
        };
        let attributes = attributes(&full);
        let workload_names: Vec<&str> = attributes
            .iter()
            .map(|(name, _)| *name)
            .skip(16)
            .collect::<Vec<_>>();
        assert_eq!(
            workload_names,
            vec![
                PROCESS_PID,
                WORKLOAD_SOURCE,
                PROCESS_EXECUTABLE_PATH,
                WORKLOAD_UID,
                WORKLOAD_CGROUP_ID,
                CONTAINER_ID,
                CONTAINER_IMAGE_NAME,
                K8S_POD_NAME,
                K8S_NAMESPACE_NAME,
                WORKLOAD_SERVICE_ACCOUNT,
                WORKLOAD_UNIT,
            ]
        );
        assert_eq!(value(&attributes, PROCESS_PID), Some("4242"));
        assert_eq!(
            value(&attributes, PROCESS_EXECUTABLE_PATH),
            Some("/usr/bin/curl")
        );
        assert_eq!(value(&attributes, WORKLOAD_SOURCE), Some("socket"));
        assert_eq!(value(&attributes, WORKLOAD_CGROUP_ID), Some("78912"));
    }

    #[test]
    fn a_field_the_node_could_not_read_has_no_attribute() {
        let partial = FlowRecord {
            workload: Some(Workload {
                exe: None,
                uid: None,
                cgroup: None,
                container: Some(String::new()),
                image: None,
                pod: None,
                namespace: None,
                service_account: None,
                unit: None,
                ..workload()
            }),
            ..record()
        };
        let attributes = attributes(&partial);
        assert_eq!(value(&attributes, PROCESS_PID), Some("4242"));
        assert!(value(&attributes, PROCESS_EXECUTABLE_PATH).is_none());
        assert!(
            value(&attributes, CONTAINER_ID).is_none(),
            "an empty container id is absence, not a container called nothing"
        );
        assert!(value(&attributes, WORKLOAD_UID).is_none());
    }

    #[test]
    fn a_protocol_with_no_conventional_word_still_carries_its_number() {
        let esp = FlowRecord {
            protocol: 50,
            ..record()
        };
        let attributes = attributes(&esp);
        assert!(
            value(&attributes, NETWORK_TRANSPORT).is_none(),
            "the conventions name tcp and udp, and inventing a third word is drift"
        );
        assert_eq!(value(&attributes, FLOW_PROTOCOL_NUMBER), Some("50"));
    }

    #[test]
    fn an_ipv6_flow_says_so() {
        let v6 = FlowRecord {
            src: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7)),
            dst: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9)),
            protocol: 17,
            ..record()
        };
        let attributes = attributes(&v6);
        assert_eq!(value(&attributes, NETWORK_TYPE), Some("ipv6"));
        assert_eq!(value(&attributes, NETWORK_TRANSPORT), Some("udp"));
        assert_eq!(value(&attributes, SOURCE_ADDRESS), Some("2001:db8::7"));
    }

    #[test]
    fn the_body_is_the_five_tuple_a_reader_recognises() {
        assert_eq!(
            summary(&record()),
            "tcp 10.0.0.7:51234 -> 93.184.216.34:443 12 packets 2048 bytes"
        );
    }

    #[test]
    fn the_same_record_maps_to_the_same_attributes_twice() {
        let full = FlowRecord {
            workload: Some(workload()),
            ..record()
        };
        assert_eq!(
            attributes(&full),
            attributes(&full),
            "a format whose output varies between two runs of one input is not a contract"
        );
    }
}

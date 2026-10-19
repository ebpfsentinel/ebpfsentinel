//! Flow records as JSON lines: one object per line, one line per record.
//!
//! The field names are the ones the OTLP mapping already settled on, read
//! straight from its constants rather than copied, so a file tailed off disk
//! and a log pushed to a collector answer the same query. What differs is the
//! typing: a count in a JSON object is a number, because a reader indexing
//! `ebpfsentinel.flow.bytes` as a string cannot sum it.
//!
//! One line is self-contained and ends in a newline. There is no array and no
//! wrapping object, which is what lets any reader start in the middle of a
//! rotated file, and what makes a truncated last line cost one record rather
//! than the file.
//!
//! Absence is absence, as everywhere else: a field the node could not read
//! has no key, and a transited flow carries no workload key at all.

use crate::flow::entity::FlowRecord;
use crate::flow::otlp;
use crate::flow::siem::rfc3339_millis;
use crate::workload::entity::Workload;

/// The time field a reader indexes on, which is the record's own end time
/// rather than the moment the line was written: a file replayed after an
/// outage must not re-date every flow in it.
pub const TIMESTAMP: &str = "timestamp";

/// The event name, the same one the OTLP logs carry.
pub const EVENT_NAME: &str = "event.name";

/// One record as one JSON line, newline included.
#[must_use]
pub fn line(record: &FlowRecord, sampling: u32) -> String {
    let mut out = String::with_capacity(512);
    out.push('{');

    text(&mut out, TIMESTAMP, &rfc3339_millis(record.end_ms));
    text(&mut out, EVENT_NAME, otlp::EVENT_NAME);

    text(&mut out, otlp::SOURCE_ADDRESS, &record.src.to_string());
    number(&mut out, otlp::SOURCE_PORT, u64::from(record.src_port));
    text(&mut out, otlp::DESTINATION_ADDRESS, &record.dst.to_string());
    number(&mut out, otlp::DESTINATION_PORT, u64::from(record.dst_port));
    if let Some(transport) = conventional_transport(record.protocol) {
        text(&mut out, otlp::NETWORK_TRANSPORT, transport);
    }
    number(
        &mut out,
        otlp::FLOW_PROTOCOL_NUMBER,
        u64::from(record.protocol),
    );
    text(
        &mut out,
        otlp::NETWORK_TYPE,
        if record.is_ipv6() { "ipv6" } else { "ipv4" },
    );

    number(&mut out, otlp::FLOW_PACKETS, record.packets);
    number(&mut out, otlp::FLOW_BYTES, record.bytes);
    number(&mut out, otlp::FLOW_PACKETS_REVERSE, record.packets_rev);
    number(&mut out, otlp::FLOW_BYTES_REVERSE, record.bytes_rev);

    number(&mut out, otlp::FLOW_START_TIME, record.start_ms);
    number(&mut out, otlp::FLOW_END_TIME, record.end_ms);
    number(
        &mut out,
        otlp::FLOW_DURATION_MS,
        record.end_ms.saturating_sub(record.start_ms),
    );
    text(&mut out, otlp::FLOW_END_REASON, record.reason.as_str());
    number(
        &mut out,
        otlp::FLOW_END_REASON_CODE,
        u64::from(record.reason.code()),
    );
    if sampling > 1 {
        number(&mut out, otlp::FLOW_SAMPLING, u64::from(sampling));
    }

    if let Some(workload) = record.workload.as_ref() {
        write_workload(&mut out, workload);
    }

    out.push_str("}\n");
    out
}

/// The workload block, on the same names the OTLP attributes use.
fn write_workload(out: &mut String, workload: &Workload) {
    number(out, otlp::PROCESS_PID, u64::from(workload.pid));
    text(out, otlp::WORKLOAD_SOURCE, workload.source.as_str());
    optional_text(out, otlp::PROCESS_EXECUTABLE_PATH, workload.exe.as_deref());
    if let Some(uid) = workload.uid {
        number(out, otlp::WORKLOAD_UID, u64::from(uid));
    }
    if let Some(cgroup) = workload.cgroup {
        number(out, otlp::WORKLOAD_CGROUP_ID, cgroup);
    }
    optional_text(out, otlp::CONTAINER_ID, workload.container.as_deref());
    optional_text(out, otlp::CONTAINER_IMAGE_NAME, workload.image.as_deref());
    optional_text(out, otlp::K8S_POD_NAME, workload.pod.as_deref());
    optional_text(out, otlp::K8S_NAMESPACE_NAME, workload.namespace.as_deref());
    optional_text(
        out,
        otlp::WORKLOAD_SERVICE_ACCOUNT,
        workload.service_account.as_deref(),
    );
    optional_text(out, otlp::WORKLOAD_UNIT, workload.unit.as_deref());
}

/// The transport word the conventions define, or nothing for a protocol they
/// say nothing about, which is the same rule the OTLP mapping follows.
fn conventional_transport(protocol: u8) -> Option<&'static str> {
    match protocol {
        6 => Some("tcp"),
        17 => Some("udp"),
        _ => None,
    }
}

/// A string member, escaped.
fn text(out: &mut String, key: &str, value: &str) {
    separate(out);
    push_string(out, key);
    out.push(':');
    push_string(out, value);
}

/// A string member, written only where there is a value.
fn optional_text(out: &mut String, key: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        text(out, key, value);
    }
}

/// A numeric member. Every count this module writes is unsigned, so no value
/// here can carry a sign a reader has to parse.
fn number(out: &mut String, key: &str, value: u64) {
    separate(out);
    push_string(out, key);
    out.push(':');
    out.push_str(&value.to_string());
}

/// A comma, where something has already been written.
fn separate(out: &mut String) {
    if out.len() > 1 {
        out.push(',');
    }
}

/// A JSON string, with the six escapes the grammar requires and control
/// characters as `\u00XX`. A path or a container name is attacker-influenced
/// input, so a line that cannot be parsed is a line a reader drops.
fn push_string(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::flow::entity::FlowEndReason;
    use crate::workload::entity::WorkloadSource;

    fn transited() -> FlowRecord {
        FlowRecord {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            dst: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            src_port: 51_234,
            dst_port: 443,
            protocol: 6,
            packets: 12,
            bytes: 2_048,
            packets_rev: 10,
            bytes_rev: 16_384,
            start_ms: 1_760_000_000_000,
            end_ms: 1_760_000_012_500,
            reason: FlowEndReason::IdleTimeout,
            workload: None,
        }
    }

    fn parse(line: &str) -> serde_json::Value {
        serde_json::from_str(line.trim_end()).expect("the line is one JSON object")
    }

    #[test]
    fn a_record_is_one_object_on_one_line() {
        let rendered = line(&transited(), 1);
        assert!(rendered.ends_with("}\n"), "{rendered}");
        assert_eq!(rendered.matches('\n').count(), 1, "{rendered}");
        let value = parse(&rendered);
        assert_eq!(value["timestamp"], "2025-10-09T08:53:32.500Z");
        assert_eq!(value["event.name"], "ebpfsentinel.flow");
        assert_eq!(value["source.address"], "10.0.0.7");
        assert_eq!(value["network.transport"], "tcp");
        assert_eq!(value["network.type"], "ipv4");
    }

    #[test]
    fn a_count_is_a_number_a_reader_can_sum() {
        let value = parse(&line(&transited(), 1));
        assert_eq!(value["source.port"], 51_234);
        assert_eq!(value["ebpfsentinel.flow.bytes"], 2_048);
        assert_eq!(value["ebpfsentinel.flow.packets_reverse"], 10);
        assert_eq!(value["ebpfsentinel.flow.duration_ms"], 12_500);
        assert_eq!(value["ebpfsentinel.flow.end_reason_code"], 1);
        assert!(
            value["ebpfsentinel.flow.bytes"].is_number(),
            "a count written as a string cannot be summed"
        );
    }

    #[test]
    fn the_names_are_the_ones_the_otlp_mapping_settled_on() {
        let value = parse(&line(&transited(), 1));
        for (key, _) in otlp::attributes(&transited()) {
            assert!(
                value.get(key).is_some(),
                "{key} is in the OTLP mapping and not in the line"
            );
        }
    }

    #[test]
    fn a_transited_flow_carries_no_workload_key() {
        let value = parse(&line(&transited(), 1));
        assert!(value.get("process.pid").is_none());
        assert!(value.get("container.id").is_none());
        assert!(value.get("ebpfsentinel.workload.source").is_none());
    }

    #[test]
    fn a_resolved_workload_writes_its_block() {
        let record = FlowRecord {
            workload: Some(Workload {
                pid: 4_242,
                source: WorkloadSource::Socket,
                exe: Some("/usr/bin/curl".to_string()),
                uid: Some(1_000),
                cgroup: Some(9_876),
                container: Some(String::new()),
                image: None,
                pod: Some("web-0".to_string()),
                namespace: Some("shop".to_string()),
                service_account: None,
                unit: Some("nginx.service".to_string()),
            }),
            ..transited()
        };
        let value = parse(&line(&record, 1));
        assert_eq!(value["process.pid"], 4_242);
        assert_eq!(value["process.executable.path"], "/usr/bin/curl");
        assert_eq!(value["ebpfsentinel.workload.cgroup_id"], 9_876);
        assert_eq!(value["k8s.pod.name"], "web-0");
        assert_eq!(value["ebpfsentinel.workload.unit"], "nginx.service");
        assert!(
            value.get("container.id").is_none(),
            "an empty container id is absence"
        );
        assert!(value.get("container.image.name").is_none());
        assert!(value.get("ebpfsentinel.workload.service_account").is_none());
    }

    #[test]
    fn a_rate_of_one_is_not_written_and_any_other_rate_is() {
        assert!(
            parse(&line(&transited(), 1))
                .get("ebpfsentinel.flow.sampling")
                .is_none()
        );
        assert_eq!(
            parse(&line(&transited(), 64))["ebpfsentinel.flow.sampling"],
            64
        );
    }

    #[test]
    fn a_protocol_with_no_conventional_word_still_carries_its_number() {
        let mut record = transited();
        record.protocol = 253;
        let value = parse(&line(&record, 1));
        assert!(value.get("network.transport").is_none());
        assert_eq!(value["ebpfsentinel.flow.protocol_number"], 253);
    }

    #[test]
    fn a_path_that_would_break_the_grammar_is_escaped() {
        let record = FlowRecord {
            workload: Some(Workload {
                exe: Some("/tmp/od\"d\\\npath\u{1}".to_string()),
                ..Workload::new(7, WorkloadSource::Socket).expect("a pid of seven is a workload")
            }),
            ..transited()
        };
        let rendered = line(&record, 1);
        let value = parse(&rendered);
        assert_eq!(value["process.executable.path"], "/tmp/od\"d\\\npath\u{1}");
        assert!(rendered.contains("\\u0001"), "{rendered}");
    }

    #[test]
    fn the_same_record_renders_the_same_line_twice() {
        let record = transited();
        assert_eq!(line(&record, 1), line(&record, 1));
    }
}

//! The one mapping from a flow record to the field vocabulary a SIEM reads,
//! and the two envelopes that carry it: RFC 5424 syslog and CEF.
//!
//! A format is a contract, so the key names live here once rather than in
//! each sink. Two rules decide them:
//!
//! - **A key the enterprise SIEM exporters already write is written the same
//!   way here.** `src`, `dst`, `spt`, `dpt`, `proto`, `in`, `out` are CEF's
//!   own keys, and `workloadSource`, `spid`, `sproc`, `filePath`, `suid`,
//!   `cgroupId`, `containerId`, `containerImage`, `podName`, `podNamespace`,
//!   `serviceAccount` and `systemdUnit` are the names the enterprise layer
//!   gives the same fields, so an estate that moves from the open-source
//!   agent to the enterprise one keeps its correlation rules.
//! - **Everything a flow has and an alert does not is prefixed `flow`.** CEF
//!   has no key for a packet delta, a direction's reverse counters, an end
//!   reason or a sampling rate, and the reader puts an unknown key straight
//!   into its additional extensions, so an invented short name would sit in
//!   the same namespace as a future standard one.
//!
//! `cnt` is deliberately not used for the packet count. CEF defines it as a
//! base event count, and a reader that honours it multiplies the event,
//! which would turn one flow record carrying two hundred packets into two
//! hundred flow records.
//!
//! Absence is absence here too: a field the node could not read has no key
//! at all, so a correlation rule never reads `spid=0` as a process.
//!
//! The order of the pairs is the order of the pushes below and is fixed:
//! two runs over the same readings produce the same line.

use crate::flow::entity::FlowRecord;
use crate::workload::entity::Workload;

/// CEF's own keys, in CEF's spelling.
pub const KEY_SRC: &str = "src";
pub const KEY_SRC_PORT: &str = "spt";
pub const KEY_DST: &str = "dst";
pub const KEY_DST_PORT: &str = "dpt";
pub const KEY_PROTOCOL: &str = "proto";
pub const KEY_BYTES_OUT: &str = "out";
pub const KEY_BYTES_IN: &str = "in";
pub const KEY_START: &str = "start";
pub const KEY_END: &str = "end";
pub const KEY_RECEIPT_TIME: &str = "rt";
pub const KEY_PID: &str = "spid";
pub const KEY_PROCESS: &str = "sproc";
pub const KEY_FILE_PATH: &str = "filePath";
pub const KEY_UID: &str = "suid";

/// What a flow has and an alert does not.
pub const KEY_PACKETS: &str = "flowPackets";
pub const KEY_PACKETS_REVERSE: &str = "flowPacketsReverse";
pub const KEY_DURATION: &str = "flowDurationMs";
pub const KEY_END_REASON: &str = "flowEndReason";
pub const KEY_SAMPLING: &str = "flowSampling";

/// The workload block, in the enterprise layer's spelling.
pub const KEY_WORKLOAD_SOURCE: &str = "workloadSource";
pub const KEY_CGROUP_ID: &str = "cgroupId";
pub const KEY_CONTAINER_ID: &str = "containerId";
pub const KEY_CONTAINER_IMAGE: &str = "containerImage";
pub const KEY_POD_NAME: &str = "podName";
pub const KEY_POD_NAMESPACE: &str = "podNamespace";
pub const KEY_SERVICE_ACCOUNT: &str = "serviceAccount";
pub const KEY_SYSTEMD_UNIT: &str = "systemdUnit";

/// The vendor and product a reader keys its parser on. They are the strings
/// the enterprise exporters already send, because a SIEM that learned to
/// parse one agent's CEF must not need a second rule for the other's.
pub const CEF_VENDOR: &str = "eBPFsentinel";
pub const CEF_PRODUCT: &str = "Agent";

/// The signature and the name every flow record carries, which is what tells
/// a reader holding alerts and flows from one agent which of the two it has.
pub const CEF_SIGNATURE_ID: &str = "flow";
pub const CEF_NAME: &str = "network flow";

/// A flow record is an observation, not a finding. CEF's scale runs to ten
/// and the lowest alert this product sends is a three, so a one is the honest
/// place for a record nobody pages on.
pub const CEF_SEVERITY: u8 = 1;

/// Informational, in RFC 5424's numbering. Same reasoning.
pub const SYSLOG_SEVERITY: u8 = 6;

/// The application name the syslog header carries.
pub const SYSLOG_APP_NAME: &str = "ebpfsentinel";

/// The message id of a plain syslog flow record.
pub const SYSLOG_MSG_ID: &str = "flow";

/// The message id of a CEF payload, which is the word every collector's CEF
/// rule already looks for in that position.
pub const SYSLOG_CEF_MSG_ID: &str = "CEF";

/// The fields of one flow record, in the order they are written.
///
/// `proto` carries the protocol's name, and `proto-<n>` where the number has
/// no usual name, so a reader never has to decide what an absent protocol
/// means.
#[must_use]
pub fn fields(record: &FlowRecord) -> Vec<(&'static str, String)> {
    let mut fields = Vec::with_capacity(24);

    fields.push((KEY_RECEIPT_TIME, record.end_ms.to_string()));
    fields.push((KEY_SRC, record.src.to_string()));
    fields.push((KEY_SRC_PORT, record.src_port.to_string()));
    fields.push((KEY_DST, record.dst.to_string()));
    fields.push((KEY_DST_PORT, record.dst_port.to_string()));
    fields.push((KEY_PROTOCOL, record.protocol_name()));

    fields.push((KEY_BYTES_OUT, record.bytes.to_string()));
    fields.push((KEY_BYTES_IN, record.bytes_rev.to_string()));
    fields.push((KEY_PACKETS, record.packets.to_string()));
    fields.push((KEY_PACKETS_REVERSE, record.packets_rev.to_string()));

    fields.push((KEY_START, record.start_ms.to_string()));
    fields.push((KEY_END, record.end_ms.to_string()));
    fields.push((
        KEY_DURATION,
        record.end_ms.saturating_sub(record.start_ms).to_string(),
    ));
    fields.push((KEY_END_REASON, record.reason.as_str().to_string()));

    if let Some(workload) = record.workload.as_ref() {
        push_workload(&mut fields, workload);
    }

    fields
}

/// The workload block, present only where the node resolved one. A transited
/// flow carries none of these keys rather than carrying them empty.
fn push_workload(fields: &mut Vec<(&'static str, String)>, workload: &Workload) {
    fields.push((KEY_WORKLOAD_SOURCE, workload.source.as_str().to_string()));
    fields.push((KEY_PID, workload.pid.to_string()));
    if let Some(exe) = workload.exe.as_deref().filter(|exe| !exe.is_empty()) {
        fields.push((KEY_PROCESS, binary_name(exe).to_string()));
        fields.push((KEY_FILE_PATH, exe.to_string()));
    }
    if let Some(uid) = workload.uid {
        fields.push((KEY_UID, uid.to_string()));
    }
    if let Some(cgroup) = workload.cgroup {
        fields.push((KEY_CGROUP_ID, cgroup.to_string()));
    }
    push_text(fields, KEY_CONTAINER_ID, workload.container.as_deref());
    push_text(fields, KEY_CONTAINER_IMAGE, workload.image.as_deref());
    push_text(fields, KEY_POD_NAME, workload.pod.as_deref());
    push_text(fields, KEY_POD_NAMESPACE, workload.namespace.as_deref());
    push_text(
        fields,
        KEY_SERVICE_ACCOUNT,
        workload.service_account.as_deref(),
    );
    push_text(fields, KEY_SYSTEMD_UNIT, workload.unit.as_deref());
}

/// The executable's own name, which is what CEF's `sproc` holds while the
/// whole path goes in `filePath`.
fn binary_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// A key is written only where its value is something.
fn push_text(fields: &mut Vec<(&'static str, String)>, key: &'static str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        fields.push((key, value.to_string()));
    }
}

/// The sampling rate, which rides the record only where it is not one.
///
/// No format on this page expresses flow-level selection, so a reader that
/// is never told the rate scales nothing back up. One is left out because a
/// record that says it was sampled at one in one is noise.
#[must_use]
pub fn sampling_field(sampling: u32) -> Option<(&'static str, String)> {
    (sampling > 1).then(|| (KEY_SAMPLING, sampling.to_string()))
}

/// The extension half of a CEF message, and the whole message of a plain
/// syslog record: `key=value` pairs separated by single spaces.
#[must_use]
pub fn extension(fields: &[(&'static str, String)]) -> String {
    let mut out = String::with_capacity(fields.len() * 24);
    for (index, (key, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        out.push_str(key);
        out.push('=');
        out.push_str(&escape_extension(value));
    }
    out
}

/// One CEF message for one record, header and extension.
///
/// `device_version` is the agent's own version, which is what a reader uses
/// to tell two generations of the same sender apart.
#[must_use]
pub fn cef(record: &FlowRecord, device_version: &str, sampling: u32) -> String {
    let mut fields = fields(record);
    fields.extend(sampling_field(sampling));
    format!(
        "CEF:0|{}|{}|{}|{}|{}|{}|{}",
        escape_header(CEF_VENDOR),
        escape_header(CEF_PRODUCT),
        escape_header(device_version),
        escape_header(CEF_SIGNATURE_ID),
        escape_header(CEF_NAME),
        CEF_SEVERITY,
        extension(&fields)
    )
}

/// One plain syslog message for one record: the same fields, no CEF header.
#[must_use]
pub fn syslog_message(record: &FlowRecord, sampling: u32) -> String {
    let mut fields = fields(record);
    fields.extend(sampling_field(sampling));
    extension(&fields)
}

/// An RFC 5424 frame around a payload.
///
/// The timestamp is the record's own end time rather than the moment of the
/// send, so a message delayed by a collector that was down still says when
/// the flow ended. The structured-data field is `-`: RFC 5424 requires a
/// registered enterprise number for any SD-ID of one's own, and this project
/// holds none, so the fields ride the message where every reader can see
/// them instead of under an SD-ID borrowed from somebody else.
#[must_use]
pub fn rfc5424(
    facility: u8,
    hostname: &str,
    msg_id: &str,
    timestamp_unix_ms: u64,
    payload: &str,
) -> String {
    let priority = u16::from(facility) * 8 + u16::from(SYSLOG_SEVERITY);
    format!(
        "<{priority}>1 {} {} {SYSLOG_APP_NAME} - {msg_id} - {payload}",
        rfc3339_millis(timestamp_unix_ms),
        printable_or_nil(hostname),
    )
}

/// A header field cannot be empty: RFC 5424 writes a `-` where the sender
/// has nothing, and a space in it would shift every field after it.
fn printable_or_nil(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .filter(|c| c.is_ascii_graphic() && *c != ' ')
        .collect();
    if cleaned.is_empty() {
        "-".to_string()
    } else {
        cleaned
    }
}

/// Unix milliseconds as an RFC 3339 timestamp in UTC, to the millisecond.
///
/// Written here rather than taken from a calendar library because the domain
/// layer carries no such dependency, and because the only calendar question
/// this project asks is this one.
#[must_use]
pub fn rfc3339_millis(unix_ms: u64) -> String {
    let seconds = unix_ms / 1_000;
    let millis = unix_ms % 1_000;
    let days = i64::try_from(seconds / 86_400).unwrap_or(0);
    let second_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = second_of_day / 3_600;
    let minute = (second_of_day % 3_600) / 60;
    let second = second_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Days since the Unix epoch to a civil date, by Howard Hinnant's algorithm:
/// the era arithmetic that every date library implements, and the reason the
/// leap years need no table.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = u64::try_from(z - era * 146_097).unwrap_or(0);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = i64::try_from(yoe).unwrap_or(0) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (
        year,
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

/// A CEF header field: the pipe that separates the fields and the backslash
/// that escapes it are the two characters that cannot travel raw.
fn escape_header(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
}

/// A CEF extension value: the equals sign ends a value, and a newline ends
/// the message, so both are escaped or removed. A space is left alone,
/// because a value runs to the next `key=`.
fn escape_extension(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\n', " ")
        .replace('\r', "")
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

    fn resolved() -> FlowRecord {
        FlowRecord {
            workload: Some(Workload {
                pid: 4_242,
                source: WorkloadSource::Socket,
                exe: Some("/usr/bin/curl".to_string()),
                uid: Some(1_000),
                cgroup: Some(9_876),
                container: Some("c0ffee".to_string()),
                image: Some("docker.io/library/nginx:1.27".to_string()),
                pod: Some("web-0".to_string()),
                namespace: Some("shop".to_string()),
                service_account: Some("web".to_string()),
                unit: Some("nginx.service".to_string()),
            }),
            ..transited()
        }
    }

    #[test]
    fn the_shared_vocabulary_is_the_one_the_enterprise_layer_writes() {
        // These are the keys the enterprise SIEM exporters put on an alert
        // for the same fields. An operator correlating a flow with an alert
        // must not have to learn two spellings, so the names are asserted
        // here rather than compared on a reader's screen.
        assert_eq!(
            [
                KEY_SRC,
                KEY_DST,
                KEY_SRC_PORT,
                KEY_DST_PORT,
                KEY_PROTOCOL,
                KEY_PID,
                KEY_PROCESS,
                KEY_FILE_PATH,
                KEY_UID,
                KEY_WORKLOAD_SOURCE,
                KEY_CGROUP_ID,
                KEY_CONTAINER_ID,
                KEY_CONTAINER_IMAGE,
                KEY_POD_NAME,
                KEY_POD_NAMESPACE,
                KEY_SERVICE_ACCOUNT,
                KEY_SYSTEMD_UNIT,
            ],
            [
                "src",
                "dst",
                "spt",
                "dpt",
                "proto",
                "spid",
                "sproc",
                "filePath",
                "suid",
                "workloadSource",
                "cgroupId",
                "containerId",
                "containerImage",
                "podName",
                "podNamespace",
                "serviceAccount",
                "systemdUnit",
            ]
        );
    }

    #[test]
    fn a_transited_flow_carries_the_five_tuple_and_no_workload() {
        let fields = fields(&transited());
        let keys: Vec<&str> = fields.iter().map(|(key, _)| *key).collect();
        assert_eq!(
            keys,
            vec![
                "rt",
                "src",
                "spt",
                "dst",
                "dpt",
                "proto",
                "out",
                "in",
                "flowPackets",
                "flowPacketsReverse",
                "start",
                "end",
                "flowDurationMs",
                "flowEndReason",
            ]
        );
    }

    #[test]
    fn a_resolved_workload_adds_its_own_block_and_nothing_else() {
        let fields = fields(&resolved());
        let keys: Vec<&str> = fields.iter().skip(14).map(|(key, _)| *key).collect();
        assert_eq!(
            keys,
            vec![
                "workloadSource",
                "spid",
                "sproc",
                "filePath",
                "suid",
                "cgroupId",
                "containerId",
                "containerImage",
                "podName",
                "podNamespace",
                "serviceAccount",
                "systemdUnit",
            ]
        );
    }

    #[test]
    fn the_process_name_is_the_binary_and_the_path_is_the_path() {
        let fields = fields(&resolved());
        let value = |key: &str| {
            fields
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| value.clone())
                .expect("the key is written")
        };
        assert_eq!(value("sproc"), "curl");
        assert_eq!(value("filePath"), "/usr/bin/curl");
    }

    #[test]
    fn a_field_the_node_could_not_read_has_no_key() {
        let mut record = resolved();
        if let Some(workload) = record.workload.as_mut() {
            workload.container = Some(String::new());
            workload.pod = None;
        }
        let rendered = extension(&fields(&record));
        assert!(!rendered.contains("containerId="), "{rendered}");
        assert!(!rendered.contains("podName="), "{rendered}");
    }

    #[test]
    fn a_protocol_with_no_usual_name_still_names_its_number() {
        let mut record = transited();
        record.protocol = 253;
        let rendered = extension(&fields(&record));
        assert!(rendered.contains("proto=proto-253"), "{rendered}");
    }

    #[test]
    fn an_ipv6_flow_writes_its_addresses_whole() {
        let mut record = transited();
        record.src = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7));
        record.dst = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9));
        let rendered = extension(&fields(&record));
        assert!(rendered.contains("src=2001:db8::7"), "{rendered}");
        assert!(rendered.contains("dst=2001:db8::9"), "{rendered}");
    }

    #[test]
    fn a_rate_of_one_is_not_written_and_any_other_rate_is() {
        assert!(sampling_field(1).is_none());
        assert_eq!(
            sampling_field(100),
            Some(("flowSampling", "100".to_string()))
        );
    }

    #[test]
    fn the_cef_header_names_the_vendor_the_product_and_the_version() {
        let message = cef(&transited(), "1.2.3", 1);
        assert!(
            message.starts_with("CEF:0|eBPFsentinel|Agent|1.2.3|flow|network flow|1|"),
            "{message}"
        );
        assert!(message.contains("src=10.0.0.7"), "{message}");
    }

    #[test]
    fn an_equals_sign_in_a_value_is_escaped_rather_than_ending_it() {
        let mut record = resolved();
        if let Some(workload) = record.workload.as_mut() {
            workload.unit = Some("odd=name.service".to_string());
        }
        let rendered = extension(&fields(&record));
        assert!(
            rendered.contains("systemdUnit=odd\\=name.service"),
            "{rendered}"
        );
    }

    #[test]
    fn a_pipe_in_a_header_field_is_escaped() {
        let message = cef(&transited(), "1.0|dev", 1);
        assert!(message.contains("1.0\\|dev"), "{message}");
    }

    #[test]
    fn the_syslog_frame_carries_the_priority_the_version_and_the_clock() {
        let record = transited();
        let message = rfc5424(16, "node-1", SYSLOG_MSG_ID, record.end_ms, "src=10.0.0.7");
        assert_eq!(
            message,
            "<134>1 2025-10-09T08:53:32.500Z node-1 ebpfsentinel - flow - src=10.0.0.7"
        );
    }

    #[test]
    fn a_hostname_with_a_space_in_it_cannot_shift_the_fields_after_it() {
        let message = rfc5424(1, "node one", SYSLOG_MSG_ID, 0, "x=1");
        assert!(message.contains(" nodeone ebpfsentinel "), "{message}");
    }

    #[test]
    fn a_node_with_no_hostname_writes_the_nil_value() {
        let message = rfc5424(1, "", SYSLOG_MSG_ID, 0, "x=1");
        assert!(message.contains(" - ebpfsentinel "), "{message}");
    }

    #[test]
    fn the_epoch_and_a_leap_day_both_render() {
        assert_eq!(rfc3339_millis(0), "1970-01-01T00:00:00.000Z");
        // 29 February 2024, which no leap table in this file knows about.
        assert_eq!(
            rfc3339_millis(1_709_164_800_000),
            "2024-02-29T00:00:00.000Z"
        );
        assert_eq!(
            rfc3339_millis(1_760_000_012_500),
            "2025-10-09T08:53:32.500Z"
        );
    }

    #[test]
    fn the_same_record_renders_the_same_line_twice() {
        let record = resolved();
        assert_eq!(cef(&record, "0.0.0-dev", 10), cef(&record, "0.0.0-dev", 10));
        assert_eq!(syslog_message(&record, 1), syslog_message(&record, 1));
    }

    #[test]
    fn a_plain_syslog_message_is_the_fields_and_no_cef_header() {
        let message = syslog_message(&transited(), 1);
        assert!(!message.contains("CEF:0"), "{message}");
        assert!(message.starts_with("rt="), "{message}");
        assert!(message.contains("flowEndReason=idle_timeout"), "{message}");
    }
}

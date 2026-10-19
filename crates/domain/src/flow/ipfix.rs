//! IPFIX encoding of flow records, as RFC 7011 writes it.
//!
//! The encoder is pure and it is the whole format: it is handed records, an
//! export time and a sequence number, and it answers with the bytes. No
//! socket, no clock and no map iteration, which is what makes the one
//! property an export format owes testable - two runs over the same records
//! produce byte-identical messages.
//!
//! ## Four templates, because absence is structural
//!
//! An IPFIX data record is positional: the template says field three is four
//! bytes and the record's third field is those four bytes, with no room for
//! "this one is missing". A single template carrying the workload block would
//! therefore force a zeroed pid onto every transited flow, which is the one
//! thing the workload block must never say. So there are four:
//!
//! | Id  | Flow        | Workload block |
//! |-----|-------------|----------------|
//! | 256 | IPv4        | absent         |
//! | 257 | IPv6        | absent         |
//! | 258 | IPv4        | present        |
//! | 259 | IPv6        | present        |
//!
//! A collector reading 256 knows there was no local process, rather than
//! reading a pid of zero and having to guess what it meant.
//!
//! ## The enterprise number is the operator's, not ours
//!
//! The workload elements are private elements, and a private element is only
//! meaningful under a Private Enterprise Number registered with IANA. We hold
//! none. Rather than squat on a number belonging to somebody else or invent
//! one, the PEN is configuration: at `0`, which is the default, the workload
//! templates are not offered and no record claims a private element. An
//! operator who registers a PEN, or who already holds one, sets it and gets
//! the block. The documentation says this in the same place it describes the
//! block, because an element decoded under the wrong PEN is a field attributed
//! to another vendor's vocabulary.
//!
//! The reverse counters need no such care: RFC 5103 registered PEN 29305 for
//! exactly them, so `reverseOctetDeltaCount` and `reversePacketDeltaCount`
//! are standard elements that any collector already understands.

use std::net::IpAddr;

use crate::flow::entity::FlowRecord;
use crate::workload::entity::present;

/// The version IPFIX puts in every message header.
pub const IPFIX_VERSION: u16 = 10;

/// Set id 2 carries template records; RFC 7011 section 3.3.2.
pub const SET_ID_TEMPLATE: u16 = 2;

/// The PEN RFC 5103 registered for the reverse direction of a biflow.
pub const PEN_REVERSE: u32 = 29_305;

/// IPv4 flow, no workload block.
pub const TEMPLATE_IPV4: u16 = 256;
/// IPv6 flow, no workload block.
pub const TEMPLATE_IPV6: u16 = 257;
/// IPv4 flow with the workload block as private elements.
pub const TEMPLATE_IPV4_WORKLOAD: u16 = 258;
/// IPv6 flow with the workload block as private elements.
pub const TEMPLATE_IPV6_WORKLOAD: u16 = 259;

/// Every template the exporter offers, in the order it sends them.
pub const TEMPLATE_IDS: [u16; 4] = [
    TEMPLATE_IPV4,
    TEMPLATE_IPV6,
    TEMPLATE_IPV4_WORKLOAD,
    TEMPLATE_IPV6_WORKLOAD,
];

const MESSAGE_HEADER_BYTES: usize = 16;
const SET_HEADER_BYTES: usize = 4;

/// What a variable-length element is cut to before it is written.
///
/// The cut is on a character boundary, so a truncated path is still valid
/// UTF-8, and it bounds one record: without it an executable path chosen by
/// whoever started the process decides the size of a datagram.
pub const MAX_VARLEN_BYTES: usize = 1_024;

/// The field count of each template, which is what the docs publish and what
/// a test pins so a field added without a documentation change fails.
const BASE_FIELD_COUNT: u16 = 12;
const WORKLOAD_FIELD_COUNT: u16 = 11;

/// One field of a template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// The information element id, without the enterprise bit.
    pub element: u16,
    /// The length on the wire, or `0xFFFF` for a variable-length element.
    pub length: u16,
    /// The enterprise number, `0` for an IANA element.
    pub enterprise: u32,
}

impl Field {
    const fn iana(element: u16, length: u16) -> Self {
        Self {
            element,
            length,
            enterprise: 0,
        }
    }

    const fn private(element: u16, length: u16, enterprise: u32) -> Self {
        Self {
            element,
            length,
            enterprise,
        }
    }

    /// Whether the element's length is carried on the wire rather than in the
    /// template.
    #[must_use]
    pub fn is_variable(&self) -> bool {
        self.length == 0xFFFF
    }

    fn write_into(self, out: &mut Vec<u8>) {
        let id = if self.enterprise == 0 {
            self.element
        } else {
            self.element | 0x8000
        };
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&self.length.to_be_bytes());
        if self.enterprise != 0 {
            out.extend_from_slice(&self.enterprise.to_be_bytes());
        }
    }
}

/// What the exporter was configured with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpfixOptions {
    /// The observation domain, which is how a collector tells two exporters
    /// on one node apart.
    pub observation_domain_id: u32,
    /// The PEN the workload elements are written under. `0` means the block
    /// is not exported at all.
    pub enterprise_number: u32,
    /// The size a message is kept under where the records allow it.
    pub max_message_bytes: usize,
}

impl Default for IpfixOptions {
    fn default() -> Self {
        Self {
            observation_domain_id: 0,
            enterprise_number: 0,
            // Under the usual 1500-byte MTU with room for IP and UDP headers,
            // so a datagram is not fragmented on the way to the collector.
            max_message_bytes: 1_400,
        }
    }
}

impl IpfixOptions {
    /// Whether the workload templates are offered at all.
    #[must_use]
    pub fn exports_workload(&self) -> bool {
        self.enterprise_number != 0
    }
}

/// The encoder. It owns the sequence number and nothing else that changes.
#[derive(Debug)]
pub struct IpfixEncoder {
    options: IpfixOptions,
    sequence: u32,
}

impl IpfixEncoder {
    #[must_use]
    pub fn new(options: IpfixOptions) -> Self {
        Self {
            options,
            sequence: 0,
        }
    }

    #[must_use]
    pub fn options(&self) -> IpfixOptions {
        self.options
    }

    /// The sequence number the next message will carry: the count of data
    /// records already sent in this observation domain, which is what RFC
    /// 7011 section 3.1 says the field means.
    #[must_use]
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Start the sequence again, which is what a new connection to a
    /// collector means on a reliable transport.
    pub fn reset_sequence(&mut self) {
        self.sequence = 0;
    }

    /// The fields of one template, in the order the record writes them.
    ///
    /// Public because the documentation's field tables are generated from a
    /// test over this function rather than typed beside it: a template that
    /// gains a field and a page that does not are a collector configured
    /// wrongly.
    #[must_use]
    pub fn template_fields(&self, template: u16) -> Vec<Field> {
        let mut fields = Vec::with_capacity((BASE_FIELD_COUNT + WORKLOAD_FIELD_COUNT) as usize);
        let ipv6 = template == TEMPLATE_IPV6 || template == TEMPLATE_IPV6_WORKLOAD;
        if ipv6 {
            fields.push(Field::iana(27, 16)); // sourceIPv6Address
            fields.push(Field::iana(28, 16)); // destinationIPv6Address
        } else {
            fields.push(Field::iana(8, 4)); // sourceIPv4Address
            fields.push(Field::iana(12, 4)); // destinationIPv4Address
        }
        fields.push(Field::iana(7, 2)); // sourceTransportPort
        fields.push(Field::iana(11, 2)); // destinationTransportPort
        fields.push(Field::iana(4, 1)); // protocolIdentifier
        fields.push(Field::iana(1, 8)); // octetDeltaCount
        fields.push(Field::iana(2, 8)); // packetDeltaCount
        fields.push(Field::private(1, 8, PEN_REVERSE)); // reverseOctetDeltaCount
        fields.push(Field::private(2, 8, PEN_REVERSE)); // reversePacketDeltaCount
        fields.push(Field::iana(152, 8)); // flowStartMilliseconds
        fields.push(Field::iana(153, 8)); // flowEndMilliseconds
        fields.push(Field::iana(136, 1)); // flowEndReason

        if template == TEMPLATE_IPV4_WORKLOAD || template == TEMPLATE_IPV6_WORKLOAD {
            let pen = self.options.enterprise_number;
            fields.push(Field::private(1, 4, pen)); // workloadProcessId
            for element in 2..=WORKLOAD_FIELD_COUNT {
                fields.push(Field::private(element, 0xFFFF, pen));
            }
        }
        fields
    }

    /// The templates this exporter offers, which is three fewer than four
    /// when no enterprise number is configured.
    #[must_use]
    pub fn offered_templates(&self) -> Vec<u16> {
        if self.options.exports_workload() {
            TEMPLATE_IDS.to_vec()
        } else {
            vec![TEMPLATE_IPV4, TEMPLATE_IPV6]
        }
    }

    /// One message carrying every template, which is what is sent on the
    /// template interval and again on every reconnection.
    ///
    /// A template message carries the current sequence number without
    /// advancing it: the field counts data records, and a template is not one.
    #[must_use]
    pub fn template_message(&self, export_time_secs: u32) -> Vec<u8> {
        let mut set = Vec::new();
        for template in self.offered_templates() {
            let fields = self.template_fields(template);
            set.extend_from_slice(&template.to_be_bytes());
            let count = u16::try_from(fields.len()).unwrap_or(u16::MAX);
            set.extend_from_slice(&count.to_be_bytes());
            for field in &fields {
                field.write_into(&mut set);
            }
        }
        let mut message = Vec::with_capacity(MESSAGE_HEADER_BYTES + SET_HEADER_BYTES + set.len());
        self.write_message_header(
            &mut message,
            export_time_secs,
            self.sequence,
            SET_HEADER_BYTES + set.len(),
        );
        message.extend_from_slice(&SET_ID_TEMPLATE.to_be_bytes());
        let set_length = u16::try_from(SET_HEADER_BYTES + set.len()).unwrap_or(u16::MAX);
        message.extend_from_slice(&set_length.to_be_bytes());
        message.extend_from_slice(&set);
        message
    }

    /// The template a record is written under.
    #[must_use]
    pub fn template_of(&self, record: &FlowRecord) -> u16 {
        let workload = self.options.exports_workload() && present(&record.workload).is_some();
        match (record.is_ipv6(), workload) {
            (false, false) => TEMPLATE_IPV4,
            (true, false) => TEMPLATE_IPV6,
            (false, true) => TEMPLATE_IPV4_WORKLOAD,
            (true, true) => TEMPLATE_IPV6_WORKLOAD,
        }
    }

    /// Encode records into messages, advancing the sequence number by the
    /// number of records written.
    ///
    /// Records are kept in the order they were handed over, and consecutive
    /// records under one template share a set. A message is kept under
    /// `max_message_bytes` wherever the records allow it; a single record
    /// larger than the bound is still written, in a message of its own,
    /// because splitting a data record is not a thing IPFIX can do.
    pub fn data_messages(&mut self, records: &[FlowRecord], export_time_secs: u32) -> Vec<Vec<u8>> {
        let mut messages = Vec::new();
        let mut pending: Vec<(u16, Vec<u8>)> = Vec::new();
        let mut pending_bytes = 0usize;

        for record in records {
            let template = self.template_of(record);
            let encoded = Self::encode_record(record, template);
            let continues = pending.last().map(|(id, _)| *id) == Some(template);
            let cost = if continues {
                encoded.len()
            } else {
                SET_HEADER_BYTES + encoded.len()
            };
            if !pending.is_empty()
                && MESSAGE_HEADER_BYTES + pending_bytes + cost > self.options.max_message_bytes
            {
                messages.push(self.finish_message(&pending, export_time_secs));
                pending.clear();
                pending_bytes = 0;
            }
            let cost = if pending.last().map(|(id, _)| *id) == Some(template) {
                encoded.len()
            } else {
                SET_HEADER_BYTES + encoded.len()
            };
            pending_bytes += cost;
            pending.push((template, encoded));
        }

        if !pending.is_empty() {
            messages.push(self.finish_message(&pending, export_time_secs));
        }
        messages
    }

    /// Build one message out of the records held, grouping consecutive
    /// records of one template into a set, and advance the sequence.
    fn finish_message(&mut self, pending: &[(u16, Vec<u8>)], export_time_secs: u32) -> Vec<u8> {
        let mut body = Vec::new();
        let mut index = 0usize;
        while index < pending.len() {
            let template = pending[index].0;
            let mut set = Vec::new();
            while index < pending.len() && pending[index].0 == template {
                set.extend_from_slice(&pending[index].1);
                index += 1;
            }
            body.extend_from_slice(&template.to_be_bytes());
            let length = u16::try_from(SET_HEADER_BYTES + set.len()).unwrap_or(u16::MAX);
            body.extend_from_slice(&length.to_be_bytes());
            body.extend_from_slice(&set);
        }

        let sequence = self.sequence;
        let mut message = Vec::with_capacity(MESSAGE_HEADER_BYTES + body.len());
        self.write_message_header(&mut message, export_time_secs, sequence, body.len());
        message.extend_from_slice(&body);
        self.sequence = self
            .sequence
            .wrapping_add(u32::try_from(pending.len()).unwrap_or(u32::MAX));
        message
    }

    fn write_message_header(
        &self,
        out: &mut Vec<u8>,
        export_time_secs: u32,
        sequence: u32,
        body_bytes: usize,
    ) {
        let length = u16::try_from(MESSAGE_HEADER_BYTES + body_bytes).unwrap_or(u16::MAX);
        out.extend_from_slice(&IPFIX_VERSION.to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&export_time_secs.to_be_bytes());
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&self.options.observation_domain_id.to_be_bytes());
    }

    /// One data record, in the order `template_fields` declares.
    fn encode_record(record: &FlowRecord, template: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        match (record.src, record.dst) {
            (IpAddr::V4(src), IpAddr::V4(dst))
                if template == TEMPLATE_IPV4 || template == TEMPLATE_IPV4_WORKLOAD =>
            {
                out.extend_from_slice(&src.octets());
                out.extend_from_slice(&dst.octets());
            }
            _ => {
                out.extend_from_slice(&as_v6(record.src).octets());
                out.extend_from_slice(&as_v6(record.dst).octets());
            }
        }
        out.extend_from_slice(&record.src_port.to_be_bytes());
        out.extend_from_slice(&record.dst_port.to_be_bytes());
        out.push(record.protocol);
        out.extend_from_slice(&record.bytes.to_be_bytes());
        out.extend_from_slice(&record.packets.to_be_bytes());
        out.extend_from_slice(&record.bytes_rev.to_be_bytes());
        out.extend_from_slice(&record.packets_rev.to_be_bytes());
        out.extend_from_slice(&record.start_ms.to_be_bytes());
        out.extend_from_slice(&record.end_ms.to_be_bytes());
        out.push(record.reason.code());

        if template == TEMPLATE_IPV4_WORKLOAD || template == TEMPLATE_IPV6_WORKLOAD {
            // Reached only under a template the workload block exists for, so
            // the absent case below writes nothing rather than a zero pid.
            let workload = present(&record.workload);
            let pid = workload.map_or(0, |w| w.pid);
            out.extend_from_slice(&pid.to_be_bytes());
            write_varlen(&mut out, workload.map(|w| w.source.as_str()));
            write_varlen(&mut out, workload.and_then(|w| w.exe.as_deref()));
            let uid = workload.and_then(|w| w.uid).map(|uid| uid.to_string());
            write_varlen(&mut out, uid.as_deref());
            let cgroup = workload.and_then(|w| w.cgroup).map(|id| id.to_string());
            write_varlen(&mut out, cgroup.as_deref());
            write_varlen(&mut out, workload.and_then(|w| w.container.as_deref()));
            write_varlen(&mut out, workload.and_then(|w| w.image.as_deref()));
            write_varlen(&mut out, workload.and_then(|w| w.pod.as_deref()));
            write_varlen(&mut out, workload.and_then(|w| w.namespace.as_deref()));
            write_varlen(
                &mut out,
                workload.and_then(|w| w.service_account.as_deref()),
            );
            write_varlen(&mut out, workload.and_then(|w| w.unit.as_deref()));
        }
        out
    }
}

/// An address in sixteen bytes, v4 mapped the way RFC 4291 maps it, for the
/// record of a flow whose two ends disagree about the family. The kernel does
/// not produce such a row, and a format that cannot write one would panic on
/// the day something else does.
fn as_v6(addr: IpAddr) -> std::net::Ipv6Addr {
    match addr {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

/// A variable-length element, in the encoding RFC 7011 section 7 gives:
/// one length byte under 255, otherwise `255` and two more.
///
/// An absent value is a zero length rather than a placeholder, which is the
/// only way absence is expressible once a field's position is fixed.
fn write_varlen(out: &mut Vec<u8>, value: Option<&str>) {
    let bytes = value.map_or(&[][..], str::as_bytes);
    let bytes = if bytes.len() > MAX_VARLEN_BYTES {
        let mut end = MAX_VARLEN_BYTES;
        // Back off to a character boundary so the element stays valid UTF-8.
        while end > 0 && !value.is_some_and(|v| v.is_char_boundary(end)) {
            end -= 1;
        }
        &bytes[..end]
    } else {
        bytes
    };
    if bytes.len() < 255 {
        out.push(u8::try_from(bytes.len()).unwrap_or(0));
    } else {
        out.push(255);
        let length = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&length.to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::entity::FlowEndReason;
    use crate::workload::entity::{Workload, WorkloadSource};

    fn record() -> FlowRecord {
        FlowRecord {
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
            src_port: 51_000,
            dst_port: 443,
            protocol: 6,
            packets: 12,
            bytes: 1_500,
            packets_rev: 10,
            bytes_rev: 9_000,
            start_ms: 1_700_000_000_000,
            end_ms: 1_700_000_060_000,
            reason: FlowEndReason::ActiveTimeout,
            workload: None,
        }
    }

    fn v6_record() -> FlowRecord {
        FlowRecord {
            src: "2001:db8::1".parse().unwrap(),
            dst: "2001:db8::2".parse().unwrap(),
            ..record()
        }
    }

    fn with_workload() -> FlowRecord {
        let workload = Workload::new(4_242, WorkloadSource::Socket).map(|w| {
            let mut w = w;
            w.exe = Some("/usr/bin/curl".to_string());
            w.uid = Some(1_000);
            w.cgroup = Some(98_765);
            w.container = Some("abc123".to_string());
            w
        });
        FlowRecord {
            workload,
            ..record()
        }
    }

    fn encoder(pen: u32) -> IpfixEncoder {
        IpfixEncoder::new(IpfixOptions {
            observation_domain_id: 7,
            enterprise_number: pen,
            ..IpfixOptions::default()
        })
    }

    fn u16_at(bytes: &[u8], offset: usize) -> u16 {
        u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
    }

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    #[test]
    fn the_message_header_is_the_one_the_rfc_describes() {
        let mut encoder = encoder(0);
        let messages = encoder.data_messages(&[record()], 1_700_000_060);
        let message = &messages[0];
        assert_eq!(u16_at(message, 0), IPFIX_VERSION);
        assert_eq!(usize::from(u16_at(message, 2)), message.len());
        assert_eq!(u32_at(message, 4), 1_700_000_060);
        assert_eq!(u32_at(message, 8), 0, "the first message starts at zero");
        assert_eq!(u32_at(message, 12), 7, "the observation domain");
    }

    #[test]
    fn the_sequence_counts_data_records_and_a_template_does_not_advance_it() {
        let mut encoder = encoder(0);
        let _ = encoder.template_message(1);
        assert_eq!(encoder.sequence(), 0);
        encoder.data_messages(&[record(), record()], 1);
        assert_eq!(encoder.sequence(), 2);
        let next = encoder.data_messages(&[record()], 2);
        assert_eq!(u32_at(&next[0], 8), 2, "where the previous message ended");
        assert_eq!(encoder.sequence(), 3);
    }

    #[test]
    fn a_reconnection_starts_the_sequence_again() {
        let mut encoder = encoder(0);
        encoder.data_messages(&[record()], 1);
        encoder.reset_sequence();
        assert_eq!(encoder.sequence(), 0);
    }

    #[test]
    fn two_templates_are_offered_without_an_enterprise_number() {
        assert_eq!(
            encoder(0).offered_templates(),
            vec![TEMPLATE_IPV4, TEMPLATE_IPV6]
        );
    }

    #[test]
    fn four_templates_are_offered_once_a_pen_is_configured() {
        assert_eq!(encoder(55_555).offered_templates(), TEMPLATE_IDS.to_vec());
    }

    #[test]
    fn the_template_set_carries_set_id_two_and_every_template() {
        let encoder = encoder(55_555);
        let message = encoder.template_message(5);
        assert_eq!(u16_at(&message, 16), SET_ID_TEMPLATE);
        assert_eq!(
            usize::from(u16_at(&message, 18)),
            message.len() - MESSAGE_HEADER_BYTES
        );
        assert_eq!(u16_at(&message, 20), TEMPLATE_IPV4);
        assert_eq!(u16_at(&message, 22), BASE_FIELD_COUNT);
    }

    #[test]
    fn a_workload_template_declares_eleven_fields_more_than_the_base() {
        let encoder = encoder(55_555);
        assert_eq!(
            encoder.template_fields(TEMPLATE_IPV4).len(),
            usize::from(BASE_FIELD_COUNT)
        );
        assert_eq!(
            encoder.template_fields(TEMPLATE_IPV4_WORKLOAD).len(),
            usize::from(BASE_FIELD_COUNT + WORKLOAD_FIELD_COUNT)
        );
    }

    #[test]
    fn the_reverse_counters_are_standard_elements_under_the_rfc_5103_pen() {
        let fields = encoder(0).template_fields(TEMPLATE_IPV4);
        let reverse: Vec<&Field> = fields
            .iter()
            .filter(|f| f.enterprise == PEN_REVERSE)
            .collect();
        assert_eq!(reverse.len(), 2);
        assert_eq!(reverse[0].element, 1, "reverseOctetDeltaCount");
        assert_eq!(reverse[1].element, 2, "reversePacketDeltaCount");
    }

    #[test]
    fn the_workload_elements_carry_the_configured_enterprise_number() {
        let fields = encoder(55_555).template_fields(TEMPLATE_IPV6_WORKLOAD);
        let private: Vec<&Field> = fields.iter().filter(|f| f.enterprise == 55_555).collect();
        assert_eq!(private.len(), usize::from(WORKLOAD_FIELD_COUNT));
        assert_eq!(private[0].length, 4, "the pid is a fixed four bytes");
        assert!(private[1..].iter().all(|f| f.is_variable()));
    }

    #[test]
    fn the_enterprise_bit_is_set_on_a_private_element_and_the_pen_follows() {
        let mut out = Vec::new();
        Field::private(3, 0xFFFF, 55_555).write_into(&mut out);
        assert_eq!(u16_at(&out, 0), 0x8000 | 3);
        assert_eq!(u16_at(&out, 2), 0xFFFF);
        assert_eq!(u32_at(&out, 4), 55_555);
        assert_eq!(out.len(), 8);
    }

    #[test]
    fn an_iana_element_carries_no_enterprise_number() {
        let mut out = Vec::new();
        Field::iana(8, 4).write_into(&mut out);
        assert_eq!(out.len(), 4);
        assert_eq!(u16_at(&out, 0), 8);
    }

    #[test]
    fn a_flow_with_no_workload_is_written_under_the_plain_template() {
        let encoder = encoder(55_555);
        assert_eq!(encoder.template_of(&record()), TEMPLATE_IPV4);
        assert_eq!(encoder.template_of(&v6_record()), TEMPLATE_IPV6);
    }

    #[test]
    fn a_flow_with_a_workload_is_written_under_the_workload_template() {
        let encoder = encoder(55_555);
        assert_eq!(
            encoder.template_of(&with_workload()),
            TEMPLATE_IPV4_WORKLOAD
        );
    }

    #[test]
    fn without_a_pen_a_resolved_workload_is_not_exported_at_all() {
        let encoder = encoder(0);
        assert_eq!(encoder.template_of(&with_workload()), TEMPLATE_IPV4);
        let mut encoder = encoder;
        let messages = encoder.data_messages(&[with_workload()], 1);
        assert!(
            !messages[0].windows(4).any(|w| w == 4_242u32.to_be_bytes()),
            "no private element and so no pid on the wire"
        );
    }

    #[test]
    fn the_data_record_is_as_long_as_its_template_says() {
        let mut encoder = encoder(0);
        let messages = encoder.data_messages(&[record()], 1);
        let message = &messages[0];
        assert_eq!(u16_at(message, 16), TEMPLATE_IPV4);
        let set_length = usize::from(u16_at(message, 18));
        // 4 + 4 + 2 + 2 + 1 + 8 + 8 + 8 + 8 + 8 + 8 + 1
        assert_eq!(set_length - SET_HEADER_BYTES, 62);
    }

    #[test]
    fn an_ipv6_record_is_sixteen_bytes_an_address_wider() {
        let mut first = encoder(0);
        let four = first.data_messages(&[record()], 1)[0].len();
        let mut second = encoder(0);
        let six = second.data_messages(&[v6_record()], 1)[0].len();
        assert_eq!(six - four, 24);
    }

    #[test]
    fn the_counters_are_written_big_endian_in_the_declared_order() {
        let mut encoder = encoder(0);
        let message = encoder.data_messages(&[record()], 1).remove(0);
        let body = &message[MESSAGE_HEADER_BYTES + SET_HEADER_BYTES..];
        let mut at = 4 + 4 + 2 + 2 + 1;
        assert_eq!(
            u64::from_be_bytes(body[at..at + 8].try_into().unwrap()),
            1_500
        );
        at += 8;
        assert_eq!(u64::from_be_bytes(body[at..at + 8].try_into().unwrap()), 12);
        at += 8;
        assert_eq!(
            u64::from_be_bytes(body[at..at + 8].try_into().unwrap()),
            9_000
        );
        at += 8;
        assert_eq!(u64::from_be_bytes(body[at..at + 8].try_into().unwrap()), 10);
    }

    #[test]
    fn the_end_reason_is_the_last_byte_of_a_plain_record() {
        let mut encoder = encoder(0);
        let message = encoder.data_messages(&[record()], 1).remove(0);
        assert_eq!(
            *message.last().unwrap(),
            FlowEndReason::ActiveTimeout.code()
        );
    }

    #[test]
    fn an_absent_optional_field_of_a_present_block_is_a_zero_length() {
        let mut out = Vec::new();
        write_varlen(&mut out, None);
        assert_eq!(out, vec![0]);
    }

    #[test]
    fn a_short_string_carries_one_length_byte() {
        let mut out = Vec::new();
        write_varlen(&mut out, Some("curl"));
        assert_eq!(out, vec![4, b'c', b'u', b'r', b'l']);
    }

    #[test]
    fn a_long_string_carries_the_three_byte_length() {
        let long = "a".repeat(300);
        let mut out = Vec::new();
        write_varlen(&mut out, Some(&long));
        assert_eq!(out[0], 255);
        assert_eq!(u16_at(&out, 1), 300);
        assert_eq!(out.len(), 303);
    }

    #[test]
    fn a_string_longer_than_the_bound_is_cut_on_a_character_boundary() {
        let long = "é".repeat(MAX_VARLEN_BYTES);
        let mut out = Vec::new();
        write_varlen(&mut out, Some(&long));
        let length = usize::from(u16_at(&out, 1));
        assert!(length <= MAX_VARLEN_BYTES);
        assert!(std::str::from_utf8(&out[3..]).is_ok(), "still valid UTF-8");
    }

    #[test]
    fn consecutive_records_of_one_template_share_a_set() {
        let mut encoder = encoder(0);
        let messages = encoder.data_messages(&[record(), record()], 1);
        assert_eq!(messages.len(), 1);
        let message = &messages[0];
        assert_eq!(u16_at(message, 16), TEMPLATE_IPV4);
        assert_eq!(
            usize::from(u16_at(message, 18)),
            message.len() - MESSAGE_HEADER_BYTES,
            "one set, both records"
        );
    }

    #[test]
    fn records_of_two_templates_are_two_sets_in_one_message() {
        let mut encoder = encoder(0);
        let messages = encoder.data_messages(&[record(), v6_record()], 1);
        assert_eq!(messages.len(), 1);
        let message = &messages[0];
        let first = usize::from(u16_at(message, 18));
        assert_eq!(u16_at(message, 16), TEMPLATE_IPV4);
        assert_eq!(u16_at(message, 16 + first), TEMPLATE_IPV6);
    }

    #[test]
    fn a_message_is_split_once_it_would_pass_the_bound() {
        let mut encoder = IpfixEncoder::new(IpfixOptions {
            max_message_bytes: 200,
            ..IpfixOptions::default()
        });
        let records: Vec<FlowRecord> = (0..10).map(|_| record()).collect();
        let messages = encoder.data_messages(&records, 1);
        assert!(messages.len() > 1);
        assert!(messages.iter().all(|m| m.len() <= 200));
        assert_eq!(encoder.sequence(), 10, "every record was written once");
    }

    #[test]
    fn every_split_message_declares_its_own_length_and_sequence() {
        let mut encoder = IpfixEncoder::new(IpfixOptions {
            max_message_bytes: 200,
            ..IpfixOptions::default()
        });
        let records: Vec<FlowRecord> = (0..10).map(|_| record()).collect();
        let messages = encoder.data_messages(&records, 9);
        let mut expected = 0u32;
        for message in &messages {
            assert_eq!(usize::from(u16_at(message, 2)), message.len());
            assert_eq!(u32_at(message, 8), expected);
            let set_length = usize::from(u16_at(message, 18));
            expected += u32::try_from((set_length - SET_HEADER_BYTES) / 62).unwrap();
        }
        assert_eq!(expected, 10);
    }

    #[test]
    fn a_record_larger_than_the_bound_is_still_written_whole() {
        let mut encoder = IpfixEncoder::new(IpfixOptions {
            max_message_bytes: 32,
            ..IpfixOptions::default()
        });
        let messages = encoder.data_messages(&[record()], 1);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].len() > 32);
        assert_eq!(usize::from(u16_at(&messages[0], 2)), messages[0].len());
    }

    #[test]
    fn no_record_means_no_message() {
        let mut encoder = encoder(0);
        assert!(encoder.data_messages(&[], 1).is_empty());
        assert_eq!(encoder.sequence(), 0);
    }

    #[test]
    fn two_runs_over_the_same_records_produce_the_same_bytes() {
        let records = vec![record(), v6_record(), with_workload()];
        let run = || {
            let mut encoder = encoder(55_555);
            let mut out = encoder.template_message(1_700_000_000);
            for message in encoder.data_messages(&records, 1_700_000_000) {
                out.extend_from_slice(&message);
            }
            out
        };
        assert_eq!(run(), run(), "an export format owes this");
    }

    #[test]
    fn the_workload_block_is_written_in_the_order_the_template_declares() {
        let mut encoder = encoder(55_555);
        let message = encoder.data_messages(&[with_workload()], 1).remove(0);
        let body = &message[MESSAGE_HEADER_BYTES + SET_HEADER_BYTES..];
        let mut at = 4 + 4 + 2 + 2 + 1 + 8 * 6 + 1;
        assert_eq!(u32_at(body, at), 4_242, "the pid");
        at += 4;
        assert_eq!(body[at], 6);
        assert_eq!(&body[at + 1..at + 7], b"socket");
        at += 7;
        assert_eq!(body[at], 13);
        assert_eq!(&body[at + 1..at + 14], b"/usr/bin/curl");
        at += 14;
        assert_eq!(&body[at..at + 5], b"\x041000", "the uid as a decimal");
        at += 5;
        assert_eq!(&body[at..at + 6], b"\x0598765", "the cgroup id");
    }

    #[test]
    fn the_absent_half_of_a_present_block_costs_one_byte_a_field() {
        let mut first = encoder(55_555);
        let with = first.data_messages(&[with_workload()], 1)[0].len();
        let mut full = with_workload();
        if let Some(workload) = full.workload.as_mut() {
            workload.image = Some("ghcr.io/x".to_string());
        }
        let mut second = encoder(55_555);
        let more = second.data_messages(&[full], 1)[0].len();
        assert_eq!(more - with, 9, "the image's bytes, not a placeholder");
    }
}

//! What a traced packet carries and what the programs write back into it.
//!
//! The agent answers "why is this packet dropped" by running a crafted packet
//! through the programs that are loaded, with `BPF_PROG_TEST_RUN`. The packet
//! carries a marker every program reads before it writes, so a trace takes
//! every lookup and every decision a live packet would and changes no state.
//! The kernel side reads these values through `ebpf-helpers`, userspace
//! through this module, so the two cannot disagree on a byte.
//!
//! - **XDP**: [`XDP_TRACE_META_LEN`] bytes of metadata in front of the packet,
//!   starting with [`XDP_TRACE_MAGIC`]. Only an XDP program on this host or
//!   the test run itself can place metadata there; a wire cannot.
//! - **tc**: `skb->mark` equal to [`TC_TRACE_MARK`] and `skb->priority` equal
//!   to [`TC_TRACE_PRIORITY`]. A socket sets either only with
//!   `CAP_NET_ADMIN`, which already holds the power to detach the programs.

/// The first word of the XDP metadata of a traced packet.
pub const XDP_TRACE_MAGIC: u32 = 0x5452_4345;

/// `skb->mark` of a traced packet.
pub const TC_TRACE_MARK: u32 = 0x5452_4345;

/// `skb->priority` of a traced packet.
pub const TC_TRACE_PRIORITY: u32 = 0xEB5E_0001;

/// The bytes of XDP metadata a trace carries: the magic word, the number of
/// records written, and three records of eight bytes. 32 is also the most
/// metadata the kernel lets a test run carry.
pub const XDP_TRACE_META_LEN: usize = 32;

/// Where the record count sits in the XDP metadata.
pub const XDP_COUNT_OFF: usize = 4;

/// Where the first record sits in the XDP metadata.
pub const XDP_RECORDS_OFF: usize = 8;

/// How many records the XDP metadata holds, one per stage of the chain.
pub const XDP_TRACE_RECORDS: u32 = 3;

/// The first word of `skb->cb` once a tc classifier recorded its decision.
pub const TC_VERDICT_MAGIC: u32 = 0x5645_5244;

/// The rule identifier a record carries when no rule decided: a default, a
/// list, a rate.
pub const NO_RULE: u32 = u32::MAX;

/// The rule identifier a firewall record carries when a fast-path map
/// decided. Those maps answer with an action and no rule index, so the record
/// says which map answered and userspace names the rule from its own copy.
pub mod fast_path {
    /// The source-prefix trie.
    pub const LPM_SRC: u32 = 0xFFFF_FF01;
    /// The destination-prefix trie.
    pub const LPM_DST: u32 = 0xFFFF_FF02;
    /// The exact five-tuple table.
    pub const HASH_5TUPLE: u32 = 0xFFFF_FF03;
    /// The destination-port table.
    pub const HASH_PORT: u32 = 0xFFFF_FF04;
}

/// Which program recorded a decision.
pub mod stage {
    pub const FIREWALL: u8 = 1;
    pub const RATELIMIT: u8 = 2;
    pub const LOADBALANCER: u8 = 3;
    pub const CONNTRACK: u8 = 4;
    pub const SCRUB: u8 = 5;
    pub const IDS: u8 = 6;
    pub const THREATINTEL: u8 = 7;
    pub const DNS: u8 = 8;
    pub const NAT_INGRESS: u8 = 9;
    pub const NAT_EGRESS: u8 = 10;
    pub const QOS: u8 = 11;
}

/// Why a stage decided what it did, in a byte.
pub mod reason {
    /// Nothing configured matched: the stage's default applied.
    pub const DEFAULT: u8 = 0;
    /// A configured rule matched; the record carries its identifier.
    pub const RULE: u8 = 1;
    /// The flow is already established, so the rules were not consulted.
    pub const ESTABLISHED: u8 = 2;
    /// A rate or a budget was exceeded at the moment of the trace.
    pub const RATE: u8 = 3;
    /// An address or a name is on a list.
    pub const LIST: u8 = 4;
    /// The packet is malformed or not something the stage classifies.
    pub const MALFORMED: u8 = 5;
    /// The stage is switched off.
    pub const DISABLED: u8 = 6;
    /// The packet would be rewritten (translated, normalised, marked).
    pub const REWRITE: u8 = 7;
}

/// One stage's decision, as a program left it for a traced packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceRecord {
    /// One of [`stage`].
    pub stage: u8,
    /// The program's return code: an XDP action, or a tc action.
    pub action: u32,
    /// One of [`reason`].
    pub reason: u8,
    /// The rule that decided, [`NO_RULE`], or a [`fast_path`] identifier.
    pub rule_id: u32,
    /// A stage-specific value: the conntrack state, the IDS sampling, the
    /// QoS class. Zero for an XDP stage.
    pub detail: u32,
}

/// The metadata a traced XDP packet starts with: the magic and no record.
#[must_use]
pub fn xdp_trace_metadata() -> [u8; XDP_TRACE_META_LEN] {
    let mut meta = [0u8; XDP_TRACE_META_LEN];
    meta[..4].copy_from_slice(&XDP_TRACE_MAGIC.to_ne_bytes());
    meta
}

/// The records the XDP stages appended, read from the metadata the test run
/// handed back. Nothing when the metadata is not a trace's.
#[must_use]
pub fn xdp_records(meta: &[u8]) -> ([Option<TraceRecord>; XDP_TRACE_RECORDS as usize], usize) {
    let mut out = [None; XDP_TRACE_RECORDS as usize];
    if meta.len() < XDP_TRACE_META_LEN || word(meta, 0) != XDP_TRACE_MAGIC {
        return (out, 0);
    }
    let count = (word(meta, XDP_COUNT_OFF) as usize).min(XDP_TRACE_RECORDS as usize);
    for (i, slot) in out.iter_mut().enumerate().take(count) {
        let at = XDP_RECORDS_OFF + i * 8;
        *slot = Some(TraceRecord {
            stage: meta[at],
            action: u32::from(meta[at + 1]),
            reason: meta[at + 2],
            rule_id: word(meta, at + 4),
            detail: 0,
        });
    }
    (out, count)
}

/// The record a tc classifier left in `skb->cb`, with the action the run
/// returned. Nothing when the classifier recorded nothing.
#[must_use]
pub fn tc_record(cb: &[u32; 5], retval: u32) -> Option<TraceRecord> {
    if cb[0] != TC_VERDICT_MAGIC {
        return None;
    }
    Some(TraceRecord {
        stage: (cb[1] >> 8) as u8,
        action: retval,
        reason: cb[1] as u8,
        rule_id: cb[2],
        detail: cb[3],
    })
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_records(records: &[(u8, u8, u8, u32)]) -> [u8; XDP_TRACE_META_LEN] {
        let mut meta = xdp_trace_metadata();
        meta[XDP_COUNT_OFF..XDP_COUNT_OFF + 4]
            .copy_from_slice(&(records.len() as u32).to_ne_bytes());
        for (i, (stage, action, reason, rule)) in records.iter().enumerate() {
            let at = XDP_RECORDS_OFF + i * 8;
            meta[at] = *stage;
            meta[at + 1] = *action;
            meta[at + 2] = *reason;
            meta[at + 4..at + 8].copy_from_slice(&rule.to_ne_bytes());
        }
        meta
    }

    #[test]
    fn three_records_fill_the_metadata_exactly() {
        assert_eq!(
            XDP_RECORDS_OFF + XDP_TRACE_RECORDS as usize * 8,
            XDP_TRACE_META_LEN
        );
    }

    #[test]
    fn reads_the_records_in_the_order_the_stages_wrote_them() {
        let meta = with_records(&[
            (stage::FIREWALL, 2, reason::RULE, 7),
            (stage::RATELIMIT, 2, reason::DEFAULT, NO_RULE),
        ]);
        let (records, count) = xdp_records(&meta);
        assert_eq!(count, 2);
        assert_eq!(
            records[0],
            Some(TraceRecord {
                stage: stage::FIREWALL,
                action: 2,
                reason: reason::RULE,
                rule_id: 7,
                detail: 0,
            })
        );
        assert_eq!(records[1].map(|r| r.rule_id), Some(NO_RULE));
        assert_eq!(records[2], None);
    }

    #[test]
    fn metadata_without_the_magic_is_not_a_trace() {
        let mut meta = with_records(&[(stage::FIREWALL, 1, reason::RULE, 3)]);
        meta[0] ^= 0xFF;
        assert_eq!(xdp_records(&meta).1, 0);
        assert_eq!(xdp_records(&meta[..8]).1, 0);
    }

    #[test]
    fn a_count_past_the_room_reads_only_the_room() {
        let mut meta = with_records(&[]);
        meta[XDP_COUNT_OFF..XDP_COUNT_OFF + 4].copy_from_slice(&9u32.to_ne_bytes());
        assert_eq!(xdp_records(&meta).1, XDP_TRACE_RECORDS as usize);
    }

    #[test]
    fn a_tc_record_reads_stage_and_reason_from_one_word() {
        let cb = [
            TC_VERDICT_MAGIC,
            (u32::from(stage::IDS) << 8) | u32::from(reason::RULE),
            12,
            1,
            0,
        ];
        let record = tc_record(&cb, 2).unwrap();
        assert_eq!(record.stage, stage::IDS);
        assert_eq!(record.reason, reason::RULE);
        assert_eq!(record.rule_id, 12);
        assert_eq!(record.detail, 1);
        assert_eq!(record.action, 2);
        assert_eq!(tc_record(&[0; 5], 0), None);
    }
}

//! Writing a compiled `NetworkPolicy` into the maps the cgroup hooks read.
//!
//! Both maps come out of the workload firewall's object, beside the
//! quarantine's, because the hooks consulting them are the ones attached
//! there. Every write is the whole policy, diffed against the last one: new
//! and changed prefixes go in first, then the cgroups move to their tables,
//! and only then are prefixes nobody answers to any more removed, so a pod
//! never passes through an empty table on the way to its new one.

use std::collections::{BTreeMap, BTreeSet};

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{HashMap as AyaHashMap, MapData};
use domain::common::error::DomainError;
use domain::netpol::{CompiledPolicy, Direction, PortSet};
use ebpf_common::netpol::{
    NETPOL_DIR_EGRESS, NETPOL_DIR_INGRESS, NETPOL_FLAG_EGRESS_ISOLATED, NETPOL_FLAG_ENFORCE,
    NETPOL_FLAG_INGRESS_ISOLATED, NETPOL_KEY_LEN, NETPOL_MAX_CGROUPS, NETPOL_MAX_RANGES,
    NetpolCgroup, NetpolEntry, NetpolPortRange, netpol_key_data, netpol_key_word,
    netpol_prefix_len,
};
use ports::secondary::netpol_map_port::{NetpolApplied, NetpolMapPort};
use tracing::{info, warn};

use crate::ebpf::map_store::MapStore;

/// A trie key as the diff orders it: prefix length, then data.
pub type TrieKey = (u32, [u8; NETPOL_KEY_LEN]);

/// Holds the two maps a `NetworkPolicy` is written to, and what was written.
pub struct NetpolMapManager {
    rules: LpmTrie<MapData, [u8; NETPOL_KEY_LEN], NetpolEntry>,
    cgroups: AyaHashMap<MapData, u64, NetpolCgroup>,
    held_rules: BTreeMap<TrieKey, NetpolEntry>,
    held_cgroups: BTreeMap<u64, NetpolCgroup>,
}

impl NetpolMapManager {
    /// Take the two maps out of a loaded workload firewall object.
    ///
    /// # Errors
    ///
    /// Returns an error when a map is missing from the object or carries
    /// another shape than the one declared here.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let rules = LpmTrie::try_from(
            ebpf.take_map("NETPOL_RULES")
                .ok_or_else(|| anyhow::anyhow!("map 'NETPOL_RULES' not found"))?,
        )?;
        let cgroups = AyaHashMap::try_from(
            ebpf.take_map("NETPOL_CGROUPS")
                .ok_or_else(|| anyhow::anyhow!("map 'NETPOL_CGROUPS' not found"))?,
        )?;
        info!("network policy maps acquired");
        Ok(Self {
            rules,
            cgroups,
            held_rules: BTreeMap::new(),
            held_cgroups: BTreeMap::new(),
        })
    }
}

/// The value a prefix carries, with any range past the map's width dropped.
/// The compile already reports and drops those, so this is a bound rather
/// than a second policy.
fn kernel_entry(ports: &PortSet) -> NetpolEntry {
    let mut entry = NetpolEntry {
        all: u8::from(ports.all),
        ..NetpolEntry::default()
    };
    for (slot, range) in entry
        .ranges
        .iter_mut()
        .zip(ports.ranges.iter().take(NETPOL_MAX_RANGES))
    {
        *slot = NetpolPortRange {
            protocol: range.protocol,
            _pad: 0,
            lo: range.lo,
            hi: range.hi,
        };
        entry.count += 1;
    }
    entry
}

/// Every trie entry of `policy`, keyed as the kernel looks them up.
pub fn kernel_rules(policy: &CompiledPolicy) -> BTreeMap<TrieKey, NetpolEntry> {
    let mut rules = BTreeMap::new();
    for (slot, program) in policy.slots.iter().enumerate() {
        let Ok(slot) = u16::try_from(slot) else {
            break;
        };
        for entry in &program.entries {
            let direction = match entry.direction {
                Direction::Ingress => NETPOL_DIR_INGRESS,
                Direction::Egress => NETPOL_DIR_EGRESS,
            };
            let word = netpol_key_word(slot, entry.prefix.is_v6(), direction);
            rules.insert(
                (
                    netpol_prefix_len(entry.prefix.len()),
                    netpol_key_data(word, entry.prefix.octets()),
                ),
                kernel_entry(&entry.ports),
            );
        }
    }
    rules
}

/// Every cgroup of a selected pod with the table it answers to, at most
/// `NETPOL_MAX_CGROUPS` of them, and how many did not fit.
pub fn kernel_cgroups(
    policy: &CompiledPolicy,
    cgroups: &BTreeMap<u64, String>,
    enforce: bool,
) -> (BTreeMap<u64, NetpolCgroup>, usize) {
    let mut held = BTreeMap::new();
    let mut dropped = 0usize;
    for (cgroup, uid) in cgroups {
        let Some(assignment) = policy.pods.get(uid) else {
            continue;
        };
        if held.len() >= NETPOL_MAX_CGROUPS as usize {
            dropped += 1;
            continue;
        }
        let mut flags = 0u8;
        if assignment.ingress_isolated {
            flags |= NETPOL_FLAG_INGRESS_ISOLATED;
        }
        if assignment.egress_isolated {
            flags |= NETPOL_FLAG_EGRESS_ISOLATED;
        }
        if enforce {
            flags |= NETPOL_FLAG_ENFORCE;
        }
        held.insert(
            *cgroup,
            NetpolCgroup {
                slot: assignment.slot,
                flags,
                _pad: [0; 5],
            },
        );
    }
    (held, dropped)
}

impl NetpolMapPort for NetpolMapManager {
    fn apply(
        &mut self,
        policy: &CompiledPolicy,
        cgroups: &BTreeMap<u64, String>,
        enforce: bool,
    ) -> Result<NetpolApplied, DomainError> {
        let rules = kernel_rules(policy);
        let (wanted, dropped) = kernel_cgroups(policy, cgroups, enforce);

        for (key, entry) in &rules {
            if self.held_rules.get(key) == Some(entry) {
                continue;
            }
            self.rules
                .insert(&Key::new(key.0, key.1), *entry, 0)
                .map_err(|e| {
                    DomainError::EngineError(format!("NETPOL_RULES insert failed: {e}"))
                })?;
            self.held_rules.insert(*key, *entry);
        }
        for (cgroup, entry) in &wanted {
            if self.held_cgroups.get(cgroup) == Some(entry) {
                continue;
            }
            self.cgroups.insert(*cgroup, *entry, 0).map_err(|e| {
                DomainError::EngineError(format!("NETPOL_CGROUPS insert failed: {e}"))
            })?;
            self.held_cgroups.insert(*cgroup, *entry);
        }

        let stale_cgroups: BTreeSet<u64> = self
            .held_cgroups
            .keys()
            .filter(|cgroup| !wanted.contains_key(cgroup))
            .copied()
            .collect();
        for cgroup in stale_cgroups {
            // A cgroup that went away with its pod took its entry out of the
            // kernel's view of anything that matters; the remove is
            // bookkeeping and a failure of it is not an error.
            if let Err(e) = self.cgroups.remove(&cgroup) {
                warn!(cgroup, "stale network policy cgroup not removed: {e}");
            }
            self.held_cgroups.remove(&cgroup);
        }
        let stale_rules: Vec<TrieKey> = self
            .held_rules
            .keys()
            .filter(|key| !rules.contains_key(key))
            .copied()
            .collect();
        for key in stale_rules {
            self.rules.remove(&Key::new(key.0, key.1)).map_err(|e| {
                DomainError::EngineError(format!("NETPOL_RULES remove failed: {e}"))
            })?;
            self.held_rules.remove(&key);
        }

        Ok(NetpolApplied {
            entries: self.held_rules.len(),
            cgroups: self.held_cgroups.len(),
            cgroups_dropped: dropped,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use domain::netpol::{NetPrefix, PodAssignment, PortRange, SlotEntry, SlotProgram};

    fn policy() -> CompiledPolicy {
        let mut policy = CompiledPolicy::default();
        policy.slots.push(SlotProgram {
            ingress_isolated: true,
            egress_isolated: false,
            entries: vec![SlotEntry {
                direction: Direction::Ingress,
                prefix: NetPrefix::parse("10.1.0.0/16").unwrap(),
                ports: PortSet {
                    all: false,
                    ranges: vec![PortRange {
                        protocol: 6,
                        lo: 80,
                        hi: 443,
                    }],
                },
            }],
        });
        policy.slots.push(SlotProgram {
            ingress_isolated: false,
            egress_isolated: true,
            entries: vec![SlotEntry {
                direction: Direction::Egress,
                prefix: NetPrefix::parse("fd00::/8").unwrap(),
                ports: PortSet::all(),
            }],
        });
        policy.pods.insert(
            "web".into(),
            PodAssignment {
                slot: 0,
                ingress_isolated: true,
                egress_isolated: false,
            },
        );
        policy.pods.insert(
            "job".into(),
            PodAssignment {
                slot: 1,
                ingress_isolated: false,
                egress_isolated: true,
            },
        );
        policy
    }

    #[test]
    fn each_slot_entry_becomes_one_key_of_its_own_word() {
        let rules = kernel_rules(&policy());
        assert_eq!(rules.len(), 2);
        let (key, entry) = rules.iter().find(|((len, _), _)| *len == 48).unwrap();
        assert_eq!(
            &key.1[..4],
            &netpol_key_word(0, false, NETPOL_DIR_INGRESS).to_be_bytes()
        );
        assert_eq!(&key.1[4..6], &[10, 1]);
        assert_eq!(entry.count, 1);
        assert_eq!(entry.all, 0);
        assert_eq!((entry.ranges[0].lo, entry.ranges[0].hi), (80, 443));
        let (key, entry) = rules.iter().find(|((len, _), _)| *len == 40).unwrap();
        assert_eq!(
            &key.1[..4],
            &netpol_key_word(1, true, NETPOL_DIR_EGRESS).to_be_bytes()
        );
        assert_eq!(key.1[4], 0xfd);
        assert_eq!(entry.all, 1);
    }

    #[test]
    fn only_cgroups_of_selected_pods_are_written_with_their_flags() {
        let cgroups: BTreeMap<u64, String> = [
            (11, "web".to_string()),
            (12, "web".to_string()),
            (21, "job".to_string()),
            (31, "open".to_string()),
        ]
        .into_iter()
        .collect();
        let (held, dropped) = kernel_cgroups(&policy(), &cgroups, true);
        assert_eq!(dropped, 0);
        assert_eq!(held.len(), 3);
        assert_eq!(
            held[&11].flags,
            NETPOL_FLAG_INGRESS_ISOLATED | NETPOL_FLAG_ENFORCE
        );
        assert_eq!(held[&21].slot, 1);
        assert_eq!(
            held[&21].flags,
            NETPOL_FLAG_EGRESS_ISOLATED | NETPOL_FLAG_ENFORCE
        );
        let (observed, _) = kernel_cgroups(&policy(), &cgroups, false);
        assert_eq!(observed[&11].flags & NETPOL_FLAG_ENFORCE, 0);
    }

    #[test]
    fn a_range_past_the_width_is_bounded() {
        let ports = PortSet {
            all: false,
            ranges: (0..20)
                .map(|n| PortRange {
                    protocol: 17,
                    lo: n * 10,
                    hi: n * 10,
                })
                .collect(),
        };
        let entry = kernel_entry(&ports);
        assert_eq!(usize::from(entry.count), NETPOL_MAX_RANGES);
    }

    #[test]
    fn new_refuses_an_object_without_the_policy_maps() {
        let mut store = crate::ebpf::map_store::TokenMaps::default();
        match NetpolMapManager::new(&mut store) {
            Ok(_) => panic!("an object with no maps must not yield a manager"),
            Err(err) => assert!(err.to_string().contains("NETPOL_RULES")),
        }
    }
}

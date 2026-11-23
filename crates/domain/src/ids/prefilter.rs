//! Which content rules are worth running on a payload.
//!
//! Rules are grouped by the port they are keyed on, and a rule naming no
//! port, or more than an index holds, sits in one group every packet
//! consults. Each group holds two
//! Aho-Corasick automata over the fast patterns of its rules (one matching
//! bytes exactly, one folding ASCII case), so a payload is scanned once per
//! group and only the rules whose fast pattern it holds, plus the rules
//! that have none, are run in full.

use std::collections::HashMap;
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

use super::sig::inspect::{Needle, Program};

/// The candidate index of a rule set, built from the rules' fast patterns.
#[derive(Debug, Default)]
pub struct Prefilter {
    groups: HashMap<u16, Group>,
    /// The rules keyed on no port: consulted for every packet.
    every: Option<Group>,
}

#[derive(Debug, Default)]
struct Group {
    exact: Option<Automaton>,
    nocase: Option<Automaton>,
    /// Rules without a fast pattern: candidates for every payload.
    always: Vec<usize>,
}

#[derive(Debug)]
struct Automaton {
    searcher: AhoCorasick,
    /// The rules behind each pattern, by pattern id.
    rules: Vec<Vec<usize>>,
}

/// What the index needs to know of one rule.
pub struct Entry<'a> {
    /// The ports the rule is keyed on, `None` for every port.
    pub ports: Option<Vec<u16>>,
    /// `None` for a rule that names no content: a regex rule, or an
    /// imported rule whose program reads no payload content.
    pub needle: Option<&'a Needle>,
}

#[derive(Default)]
struct Builder {
    exact: Needles,
    nocase: Needles,
    always: Vec<usize>,
}

#[derive(Default)]
struct Needles {
    ids: HashMap<Vec<u8>, usize>,
    bytes: Vec<Vec<u8>>,
    rules: Vec<Vec<usize>>,
}

impl Builder {
    fn finish(self) -> Group {
        let mut always = self.always;
        let exact = self.exact.build(false, &mut always);
        let nocase = self.nocase.build(true, &mut always);
        Group {
            exact,
            nocase,
            always,
        }
    }
}

impl Needles {
    fn add(&mut self, bytes: Vec<u8>, rule: usize) {
        let id = *self.ids.entry(bytes.clone()).or_insert_with(|| {
            self.bytes.push(bytes);
            self.rules.push(Vec::new());
            self.bytes.len() - 1
        });
        self.rules[id].push(rule);
    }

    /// The automaton, or, past its size limits, the rules it would have
    /// held, which then stay candidates for every payload.
    fn build(self, nocase: bool, always: &mut Vec<usize>) -> Option<Automaton> {
        if self.bytes.is_empty() {
            return None;
        }
        if let Ok(searcher) = AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .ascii_case_insensitive(nocase)
            .build(&self.bytes)
        {
            Some(Automaton {
                searcher,
                rules: self.rules,
            })
        } else {
            always.extend(self.rules.into_iter().flatten());
            None
        }
    }
}

impl Prefilter {
    /// Index the rules, in rule order.
    #[must_use]
    pub fn build<'a>(entries: impl Iterator<Item = Entry<'a>>) -> Self {
        let mut builders: HashMap<u16, Builder> = HashMap::new();
        let mut every: Option<Builder> = None;
        for (index, entry) in entries.enumerate() {
            let add = |builder: &mut Builder| match entry.needle {
                Some(n) if n.nocase => builder.nocase.add(n.bytes.to_ascii_lowercase(), index),
                Some(n) => builder.exact.add(n.bytes.clone(), index),
                None => builder.always.push(index),
            };
            match &entry.ports {
                Some(ports) => {
                    let mut ports = ports.clone();
                    ports.sort_unstable();
                    ports.dedup();
                    for port in ports {
                        add(builders.entry(port).or_default());
                    }
                }
                None => add(every.get_or_insert_with(Builder::default)),
            }
        }
        let groups = builders
            .into_iter()
            .map(|(port, b)| (port, b.finish()))
            .collect();
        Self {
            groups,
            every: every.map(Builder::finish),
        }
    }

    /// The rules keyed on one of the packet's ports, or on none, whose fast
    /// pattern the payload holds, and those without one, sorted and without
    /// repeats. A packet without ports passes an empty slice.
    #[must_use]
    pub fn candidates(&self, ports: &[u16], payload: &[u8]) -> Vec<usize> {
        let mut out = Vec::new();
        let mut seen_ports: Vec<u16> = ports.to_vec();
        seen_ports.sort_unstable();
        seen_ports.dedup();
        let keyed = seen_ports.iter().filter_map(|port| self.groups.get(port));
        for group in keyed.chain(self.every.as_ref()) {
            out.extend_from_slice(&group.always);
            for automaton in [&group.exact, &group.nocase].into_iter().flatten() {
                let mut seen: Vec<usize> = automaton
                    .searcher
                    .find_overlapping_iter(payload)
                    .map(|m| m.pattern().as_usize())
                    .collect();
                seen.sort_unstable();
                seen.dedup();
                for id in seen {
                    out.extend_from_slice(&automaton.rules[id]);
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// The fast pattern of an imported rule's program.
#[must_use]
pub fn needle(program: Option<&Arc<Program>>) -> Option<&Needle> {
    program.and_then(|p| p.fast_pattern())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn needle(bytes: &[u8], nocase: bool) -> Needle {
        Needle {
            bytes: bytes.to_vec(),
            nocase,
        }
    }

    fn index(rules: &[(Option<&[u16]>, Option<&Needle>)]) -> Prefilter {
        Prefilter::build(rules.iter().map(|(ports, needle)| Entry {
            ports: ports.map(<[u16]>::to_vec),
            needle: *needle,
        }))
    }

    #[test]
    fn a_payload_without_the_fast_pattern_runs_no_rule() {
        let admin = needle(b"/admin", false);
        let p = index(&[(Some(&[80]), Some(&admin))]);
        assert!(p.candidates(&[80, 40000], b"GET /index").is_empty());
        assert_eq!(p.candidates(&[80, 40000], b"GET /admin"), vec![0]);
    }

    #[test]
    fn a_nocase_pattern_matches_in_either_case_and_an_exact_one_does_not() {
        let upper = needle(b"ADMIN", true);
        let exact = needle(b"ADMIN", false);
        let p = index(&[(Some(&[80]), Some(&upper)), (Some(&[80]), Some(&exact))]);
        assert_eq!(p.candidates(&[80, 1], b"xx admin xx"), vec![0]);
        assert_eq!(p.candidates(&[80, 1], b"xx ADMIN xx"), vec![0, 1]);
    }

    #[test]
    fn a_rule_without_a_fast_pattern_is_always_a_candidate_on_its_port() {
        let p = index(&[(Some(&[22]), None)]);
        assert_eq!(p.candidates(&[22, 5], b"anything"), vec![0]);
        assert!(p.candidates(&[23, 5], b"anything").is_empty());
    }

    #[test]
    fn a_rule_is_found_from_either_port_it_names_once() {
        let banner = needle(b"SSH-", false);
        let p = index(&[(Some(&[22, 2222]), Some(&banner))]);
        assert_eq!(p.candidates(&[5, 2222], b"SSH-2.0"), vec![0]);
        assert_eq!(p.candidates(&[22, 2222], b"SSH-2.0"), vec![0]);
    }

    #[test]
    fn rules_sharing_a_pattern_are_all_candidates_and_others_stay_out() {
        let a = needle(b"abc", false);
        let b = needle(b"zzz", false);
        let p = index(&[
            (Some(&[80]), Some(&a)),
            (Some(&[80]), Some(&b)),
            (Some(&[80]), Some(&a)),
            (Some(&[443]), Some(&a)),
        ]);
        assert_eq!(p.candidates(&[80, 1], b"..abc..abc.."), vec![0, 2]);
    }

    #[test]
    fn a_rule_on_every_port_is_a_candidate_for_every_packet_even_portless() {
        let ping = needle(b"ping", false);
        let p = index(&[(None, Some(&ping)), (Some(&[80]), None)]);
        assert_eq!(p.candidates(&[], b"a ping"), vec![0]);
        assert_eq!(p.candidates(&[80, 9], b"a ping"), vec![0, 1]);
        assert_eq!(p.candidates(&[81, 9], b"nothing"), Vec::<usize>::new());
    }
}

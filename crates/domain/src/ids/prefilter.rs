//! Which content rules are worth running on a payload.
//!
//! Rules are grouped by the port they are keyed on. Each group holds two
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
    pub ports: [Option<u16>; 2],
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
        for (index, entry) in entries.enumerate() {
            let [a, b] = entry.ports;
            let ports = a.into_iter().chain(b.filter(|b| Some(*b) != a));
            for port in ports {
                let builder = builders.entry(port).or_default();
                match entry.needle {
                    Some(n) if n.nocase => builder.nocase.add(n.bytes.to_ascii_lowercase(), index),
                    Some(n) => builder.exact.add(n.bytes.clone(), index),
                    None => builder.always.push(index),
                }
            }
        }
        let groups = builders
            .into_iter()
            .map(|(port, b)| {
                let mut always = b.always;
                let exact = b.exact.build(false, &mut always);
                let nocase = b.nocase.build(true, &mut always);
                (
                    port,
                    Group {
                        exact,
                        nocase,
                        always,
                    },
                )
            })
            .collect();
        Self { groups }
    }

    /// The rules keyed on either port whose fast pattern the payload holds,
    /// and those without one, sorted and without repeats.
    #[must_use]
    pub fn candidates(&self, ports: [u16; 2], payload: &[u8]) -> Vec<usize> {
        let mut out = Vec::new();
        let [a, b] = ports;
        for port in std::iter::once(a).chain((b != a).then_some(b)) {
            let Some(group) = self.groups.get(&port) else {
                continue;
            };
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

    fn index(rules: &[([Option<u16>; 2], Option<&Needle>)]) -> Prefilter {
        Prefilter::build(rules.iter().map(|(ports, needle)| Entry {
            ports: *ports,
            needle: *needle,
        }))
    }

    #[test]
    fn a_payload_without_the_fast_pattern_runs_no_rule() {
        let admin = needle(b"/admin", false);
        let p = index(&[([Some(80), None], Some(&admin))]);
        assert!(p.candidates([80, 40000], b"GET /index").is_empty());
        assert_eq!(p.candidates([80, 40000], b"GET /admin"), vec![0]);
    }

    #[test]
    fn a_nocase_pattern_matches_in_either_case_and_an_exact_one_does_not() {
        let upper = needle(b"ADMIN", true);
        let exact = needle(b"ADMIN", false);
        let p = index(&[
            ([Some(80), None], Some(&upper)),
            ([Some(80), None], Some(&exact)),
        ]);
        assert_eq!(p.candidates([80, 1], b"xx admin xx"), vec![0]);
        assert_eq!(p.candidates([80, 1], b"xx ADMIN xx"), vec![0, 1]);
    }

    #[test]
    fn a_rule_without_a_fast_pattern_is_always_a_candidate_on_its_port() {
        let p = index(&[([Some(22), None], None)]);
        assert_eq!(p.candidates([22, 5], b"anything"), vec![0]);
        assert!(p.candidates([23, 5], b"anything").is_empty());
    }

    #[test]
    fn a_rule_is_found_from_either_port_it_names_once() {
        let banner = needle(b"SSH-", false);
        let p = index(&[([Some(22), Some(2222)], Some(&banner))]);
        assert_eq!(p.candidates([5, 2222], b"SSH-2.0"), vec![0]);
        assert_eq!(p.candidates([22, 2222], b"SSH-2.0"), vec![0]);
    }

    #[test]
    fn rules_sharing_a_pattern_are_all_candidates_and_others_stay_out() {
        let a = needle(b"abc", false);
        let b = needle(b"zzz", false);
        let p = index(&[
            ([Some(80), None], Some(&a)),
            ([Some(80), None], Some(&b)),
            ([Some(80), None], Some(&a)),
            ([Some(443), None], Some(&a)),
        ]);
        assert_eq!(p.candidates([80, 1], b"..abc..abc.."), vec![0, 2]);
    }
}

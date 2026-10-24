//! Per-container DNS allow-lists, decided at the resolver.
//!
//! A container named here may resolve only the names its list matches; a
//! query for anything else is answered `REFUSED` by the agent's resolver
//! and never reaches an upstream. A container the configuration does not
//! name, and a source no container holds, are not governed by any list:
//! the allow-list speaks only for the containers it names.

use std::collections::BTreeMap;

use super::entity::DomainPattern;
use super::error::DnsError;

/// Most containers one configuration may name.
pub const MAX_ALLOWLIST_CONTAINERS: usize = 256;

/// Most patterns one container's list may carry.
pub const MAX_ALLOWLIST_PATTERNS: usize = 256;

/// What the allow-list says about one query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowListDecision {
    /// The container is named and the domain is on its list.
    Allowed,
    /// The container is named and the domain is not on its list.
    Refused,
    /// No list governs this source.
    Ungoverned,
}

/// The names each container may resolve.
#[derive(Debug, Clone, Default)]
pub struct DnsAllowList {
    containers: BTreeMap<String, Vec<DomainPattern>>,
}

impl DnsAllowList {
    /// Build the allow-list from `(container, patterns)` pairs.
    ///
    /// # Errors
    ///
    /// Refuses an empty or repeated container name, a pattern that does not
    /// parse, and a configuration past [`MAX_ALLOWLIST_CONTAINERS`] or
    /// [`MAX_ALLOWLIST_PATTERNS`].
    pub fn new<'a, I, P>(entries: I) -> Result<Self, DnsError>
    where
        I: IntoIterator<Item = (&'a str, P)>,
        P: IntoIterator<Item = &'a str>,
    {
        let mut containers = BTreeMap::new();
        for (name, patterns) in entries {
            let name = name.trim();
            if name.is_empty() {
                return Err(DnsError::InvalidAllowList(
                    "a container entry names no container".to_string(),
                ));
            }
            let parsed = patterns
                .into_iter()
                .map(DomainPattern::parse)
                .collect::<Result<Vec<_>, _>>()?;
            if parsed.len() > MAX_ALLOWLIST_PATTERNS {
                return Err(DnsError::InvalidAllowList(format!(
                    "container '{name}' names {} domains, at most {MAX_ALLOWLIST_PATTERNS}",
                    parsed.len()
                )));
            }
            if containers.insert(name.to_string(), parsed).is_some() {
                return Err(DnsError::InvalidAllowList(format!(
                    "container '{name}' is listed twice"
                )));
            }
            if containers.len() > MAX_ALLOWLIST_CONTAINERS {
                return Err(DnsError::InvalidAllowList(format!(
                    "more than {MAX_ALLOWLIST_CONTAINERS} containers listed"
                )));
            }
        }
        Ok(Self { containers })
    }

    /// Whether `container` is one this allow-list names.
    #[must_use]
    pub fn governs(&self, container: &str) -> bool {
        self.containers.contains_key(container)
    }

    /// How many containers the allow-list names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.containers.len()
    }

    /// Whether the allow-list names no container at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.containers.is_empty()
    }

    /// Decide a query for `domain` from `container`, or from a source no
    /// container holds when `container` is `None`.
    #[must_use]
    pub fn decide(&self, container: Option<&str>, domain: &str) -> AllowListDecision {
        let Some(patterns) = container.and_then(|name| self.containers.get(name)) else {
            return AllowListDecision::Ungoverned;
        };
        let domain = domain.trim_end_matches('.');
        if patterns.iter().any(|pattern| pattern.matches(domain)) {
            AllowListDecision::Allowed
        } else {
            AllowListDecision::Refused
        }
    }
}

/// The `REFUSED` answer to `query`, whose first question ends at
/// `question_end`.
///
/// It keeps the query's id, opcode, recursion-desired bit and question, so
/// the client matches it to what it asked, and carries no record.
#[must_use]
pub fn refused_response(query: &[u8], question_end: usize) -> Vec<u8> {
    const REFUSED: u8 = 5;
    let end = question_end.min(query.len());
    let mut out = query[..end].to_vec();
    if out.len() < 12 {
        return out;
    }
    // QR set, opcode and RD kept, AA and TC cleared.
    out[2] = 0x80 | (query[2] & 0x79);
    // RA set, Z and AD/CD cleared, RCODE refused.
    out[3] = 0x80 | REFUSED;
    // One question, nothing else.
    out[4..12].copy_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list() -> DnsAllowList {
        DnsAllowList::new([
            ("web", vec!["api.github.com", "*.debian.org"]),
            ("db", vec![]),
        ])
        .expect("the list builds")
    }

    #[test]
    fn a_named_container_resolves_only_what_its_list_matches() {
        let list = list();
        assert_eq!(
            list.decide(Some("web"), "api.github.com"),
            AllowListDecision::Allowed
        );
        assert_eq!(
            list.decide(Some("web"), "deb.debian.org."),
            AllowListDecision::Allowed,
            "the trailing root dot is not part of the comparison"
        );
        assert_eq!(
            list.decide(Some("web"), "evil.example"),
            AllowListDecision::Refused
        );
    }

    #[test]
    fn an_empty_list_refuses_every_name() {
        assert_eq!(
            list().decide(Some("db"), "api.github.com"),
            AllowListDecision::Refused
        );
    }

    #[test]
    fn a_container_the_list_does_not_name_and_an_unknown_source_are_ungoverned() {
        let list = list();
        assert_eq!(
            list.decide(Some("cache"), "evil.example"),
            AllowListDecision::Ungoverned
        );
        assert_eq!(
            list.decide(None, "evil.example"),
            AllowListDecision::Ungoverned
        );
    }

    #[test]
    fn a_repeated_container_or_a_bad_pattern_is_refused() {
        assert!(DnsAllowList::new([("web", vec!["a.example"]), ("web", vec![])]).is_err());
        assert!(DnsAllowList::new([("web", vec!["*."])]).is_err());
        assert!(DnsAllowList::new([(" ", vec!["a.example"])]).is_err());
    }

    #[test]
    fn the_refusal_keeps_the_id_and_question_and_sets_refused() {
        // id 0xbeef, RD set, one question for "a.io" type A class IN, plus an
        // EDNS additional record the answer must not echo.
        let mut query = vec![0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
        query.extend_from_slice(&[1, b'a', 2, b'i', b'o', 0, 0, 1, 0, 1]);
        let question_end = query.len();
        query.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);

        let answer = refused_response(&query, question_end);
        assert_eq!(&answer[..2], &[0xbe, 0xef]);
        assert_eq!(answer[2], 0x81, "a response, recursion desired kept");
        assert_eq!(answer[3] & 0x0f, 5, "rcode refused");
        assert_eq!(&answer[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&answer[12..], &query[12..question_end]);
    }
}

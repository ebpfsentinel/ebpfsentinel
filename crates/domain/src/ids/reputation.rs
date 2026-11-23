//! The IP reputation lists Suricata's `iprep` keyword reads.
//!
//! The configuration names a categories file (`id,short name,description`
//! per line) and the lists (`address[/prefix],category id,score` per line,
//! the score from 0 to 127). An address listed on its own carries a score in
//! every category, 0 where its lines give none, and it hides any network it
//! sits in; an address found only in a network carries the scores that
//! network's lines give, the most specific network deciding.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use super::sig::int::IntMatch;

/// What an `iprep` keyword asks of an address's score in a category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IprepTest {
    /// The address is listed.
    IsSet,
    /// The address is not listed, or scores 0 in the category.
    IsNotSet,
    /// The address is listed and its score compares.
    Score(IntMatch),
}

/// Which of a packet's addresses an `iprep` keyword reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Src,
    Dst,
    /// Either of them.
    Any,
    /// Both of them.
    Both,
}

impl Side {
    /// The side a rule names, `None` for any other word.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "src" => Some(Self::Src),
            "dst" => Some(Self::Dst),
            "any" => Some(Self::Any),
            "both" => Some(Self::Both),
            _ => None,
        }
    }
}

type Scores = HashMap<u8, u8>;

#[derive(Default)]
struct Lists {
    categories: HashMap<String, u8>,
    hosts: HashMap<IpAddr, Scores>,
    /// Networks by prefix length, longest first, keyed by the masked
    /// address.
    nets: BTreeMap<std::cmp::Reverse<(bool, u8)>, HashMap<u128, Scores>>,
}

impl Lists {
    fn score(&self, address: IpAddr, category: u8) -> Option<u8> {
        if let Some(scores) = self.hosts.get(&address) {
            return Some(scores.get(&category).copied().unwrap_or(0));
        }
        let (v6, bits) = key(address);
        self.nets
            .iter()
            .filter(|(std::cmp::Reverse((family, _)), _)| *family == v6)
            .find_map(|(std::cmp::Reverse((_, prefix)), nets)| nets.get(&mask(bits, *prefix, v6)))
            .and_then(|scores| scores.get(&category).copied())
    }
}

fn key(address: IpAddr) -> (bool, u128) {
    match address {
        IpAddr::V4(a) => (false, u128::from(u32::from(a))),
        IpAddr::V6(a) => (true, u128::from(a)),
    }
}

fn mask(bits: u128, prefix: u8, v6: bool) -> u128 {
    let width: u32 = if v6 { 128 } else { 32 };
    let keep = u32::from(prefix).min(width);
    if keep == 0 {
        return 0;
    }
    bits & (u128::MAX << (width - keep)) & (u128::MAX >> (128 - width))
}

/// The lists a ruleset's `iprep` keywords read, or why there are none.
#[derive(Clone)]
pub struct Reputation(Arc<Result<Lists, String>>);

impl Default for Reputation {
    fn default() -> Self {
        Self(Arc::new(Err(
            "the configuration names no reputation lists".to_string()
        )))
    }
}

impl fmt::Debug for Reputation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Reputation")
    }
}

impl PartialEq for Reputation {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Reputation {}

impl Reputation {
    /// Reads the categories file and the lists, each given as its name and
    /// its text or the reason it could not be read; one that could not
    /// leaves every `iprep` rule refused with that reason. Returns the
    /// reputation and the lines skipped.
    #[must_use]
    pub fn load(
        categories: (&str, Result<&str, String>),
        lists: &[(&str, Result<&str, String>)],
    ) -> (Self, Vec<String>) {
        let mut warnings = Vec::new();
        let mut out = Lists::default();
        let (name, text) = categories;
        let text = match text {
            Ok(text) => text,
            Err(reason) => return (Self(Arc::new(Err(reason))), warnings),
        };
        for (n, line) in lines(text) {
            let mut fields = line.splitn(3, ',');
            match (fields.next().map(str::parse::<u8>), fields.next()) {
                (Some(Ok(id)), Some(short)) if !short.is_empty() => {
                    out.categories.insert(short.to_string(), id);
                }
                _ => warnings.push(format!("{name} line {n}: not 'id,name,description'")),
            }
        }
        for (name, text) in lists {
            let text = match text {
                Ok(text) => text,
                Err(reason) => return (Self(Arc::new(Err(reason.clone()))), warnings),
            };
            for (n, line) in lines(text) {
                if !out.list(line) {
                    warnings.push(format!("{name} line {n}: not 'address,category,score'"));
                }
            }
        }
        (Self(Arc::new(Ok(out))), warnings)
    }

    /// The category id a rule names.
    ///
    /// # Errors
    ///
    /// Why the rule is refused: no lists, or a category they do not name.
    pub fn category(&self, name: &str) -> Result<u8, String> {
        let lists = self.0.as_ref().as_ref().map_err(Clone::clone)?;
        lists
            .categories
            .get(name)
            .copied()
            .ok_or_else(|| format!("'{name}' is not a category the configuration names"))
    }

    /// Whether a packet's addresses pass the test in the category.
    #[must_use]
    pub fn matches(
        &self,
        side: Side,
        category: u8,
        test: IprepTest,
        src: &[u8],
        dst: &[u8],
    ) -> bool {
        let Ok(lists) = self.0.as_ref() else {
            return false;
        };
        let one = |address: &[u8]| {
            let score = address_of(address).and_then(|a| lists.score(a, category));
            match test {
                IprepTest::IsSet => score.is_some(),
                IprepTest::IsNotSet => score.is_none_or(|s| s == 0),
                IprepTest::Score(m) => score.is_some_and(|s| m.matches(u64::from(s))),
            }
        };
        match side {
            Side::Src => one(src),
            Side::Dst => one(dst),
            Side::Any => one(src) || one(dst),
            Side::Both => one(src) && one(dst),
        }
    }
}

impl Lists {
    /// One list line; false when it is not one.
    fn list(&mut self, line: &str) -> bool {
        let mut fields = line.split(',');
        let (Some(address), Some(category), Some(score), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return false;
        };
        let (Ok(category), Ok(score)) = (category.trim().parse::<u8>(), score.trim().parse::<u8>())
        else {
            return false;
        };
        if score > 127 {
            return false;
        }
        let address = address.trim();
        match address.split_once('/') {
            None => {
                let Ok(ip) = address.parse::<IpAddr>() else {
                    return false;
                };
                self.hosts.entry(ip).or_default().insert(category, score);
            }
            Some((net, prefix)) => {
                let (Ok(ip), Ok(prefix)) = (net.parse::<IpAddr>(), prefix.parse::<u8>()) else {
                    return false;
                };
                let (v6, bits) = key(ip);
                if prefix > if v6 { 128 } else { 32 } {
                    return false;
                }
                self.nets
                    .entry(std::cmp::Reverse((v6, prefix)))
                    .or_default()
                    .entry(mask(bits, prefix, v6))
                    .or_default()
                    .insert(category, score);
            }
        }
        true
    }
}

/// A file's lines worth reading, numbered from 1: neither blank nor a
/// comment.
fn lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(n, l)| (n + 1, l.trim()))
        .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
}

fn address_of(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => <[u8; 4]>::try_from(bytes).ok().map(IpAddr::from),
        16 => <[u8; 16]>::try_from(bytes).ok().map(IpAddr::from),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::sig::int::IntOp;

    fn lists() -> Reputation {
        let (rep, warnings) = Reputation::load(
            ("categories", Ok("1,Bad,Known bad\n2,Good,Known good\n")),
            &[(
                "list",
                Ok(
                    "10.0.0.1,1,50\n10.0.0.2,1,200\n10.1.0.0/16,1,70\n10.1.2.3,2,5\n2001:db8::/32,2,9\nnope\n",
                ),
            )],
        );
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        rep
    }

    fn gt(n: u64) -> IprepTest {
        IprepTest::Score(IntMatch {
            op: IntOp::Gt,
            a: n,
            b: 0,
        })
    }

    #[test]
    fn a_listed_address_scores_in_every_category() {
        let rep = lists();
        let bad = rep.category("Bad").expect("named");
        let good = rep.category("Good").expect("named");
        let host = [10, 0, 0, 1];
        let other = [10, 9, 9, 9];
        assert!(rep.matches(Side::Src, bad, gt(30), &host, &other));
        assert!(rep.matches(Side::Src, good, IprepTest::IsSet, &host, &other));
        assert!(rep.matches(Side::Src, good, IprepTest::IsNotSet, &host, &other));
        assert!(!rep.matches(Side::Src, bad, IprepTest::IsNotSet, &host, &other));
        assert!(!rep.matches(Side::Both, bad, gt(30), &host, &other));
        assert!(rep.matches(Side::Any, bad, gt(30), &other, &host));
        assert!(!rep.matches(Side::Src, bad, IprepTest::IsSet, &[10, 0, 0, 2], &other));
    }

    #[test]
    fn a_network_scores_only_its_own_categories_and_a_host_hides_it() {
        let rep = lists();
        let bad = rep.category("Bad").expect("named");
        let good = rep.category("Good").expect("named");
        let in_net = [10, 1, 9, 9];
        assert!(rep.matches(Side::Src, bad, gt(60), &in_net, &in_net));
        assert!(!rep.matches(Side::Src, good, IprepTest::IsSet, &in_net, &in_net));
        let host = [10, 1, 2, 3];
        assert!(!rep.matches(Side::Src, bad, gt(60), &host, &host));
        assert!(rep.matches(Side::Src, bad, IprepTest::IsNotSet, &host, &host));
        let v6: [u8; 16] = "2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .expect("v6")
            .octets();
        assert!(rep.matches(Side::Src, good, gt(8), &v6, &v6));
    }

    #[test]
    fn no_lists_or_an_unknown_category_refuses_the_rule() {
        assert!(Reputation::default().category("Bad").is_err());
        assert!(lists().category("Nobody").is_err());
        let (rep, _) = Reputation::load(("categories", Err("gone".into())), &[]);
        assert_eq!(rep.category("Bad"), Err("gone".to_string()));
    }
}

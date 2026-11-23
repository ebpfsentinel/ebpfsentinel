//! The application fields a rule compares as a whole, outside any buffer:
//! the DNS header's numbers, the TLS version, handshake state and
//! certificate dates, and the DCE/RPC interface and operation number, each
//! read the way Suricata reads its keyword.

use super::int::{IntMatch, IntOp, number};
use crate::ids::dcerpc::uuid_of;
use crate::ids::suricata::{Compiled, Refused};
use crate::ids::tls::{STATE_CLIENT_HELLO, STATE_SERVER_HELLO};
use crate::ids::tx::{Fields, int_of};

/// One condition on a transaction side's fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldCheck {
    /// Any of the field's values holds the integer condition.
    Int(IntMatch),
    /// The handshake state is one of `any` (when not empty) and none of
    /// `none`.
    State { any: u64, none: u64 },
    /// The version is known, among `any` when not empty, and not among
    /// `none`.
    Version { any: Vec<u64>, none: Vec<u64> },
    /// The date is before (`Less`) or after (`Greater`) the given second,
    /// or that second exactly.
    Date(std::cmp::Ordering, u64),
    /// The leaf certificate has expired at the packet's time.
    Expired,
    /// The packet's time lies within the leaf certificate's validity.
    Valid,
    /// The text is in the field, or with `negated` the field is present and
    /// does not hold it.
    Contains { text: String, negated: bool },
    /// The field is the text, case aside.
    Equals(String),
    /// The call's interface is this UUID, its major version holding the
    /// condition when there is one.
    Iface {
        uuid: [u8; 16],
        version: Option<IntMatch>,
    },
    /// The integer lies within one of the inclusive ranges.
    Ranges(Vec<(u64, u64)>),
}

fn refused(keyword: &str, reason: impl Into<String>) -> Refused {
    Refused::new(keyword, reason)
}

/// The field a keyword reads and the condition it puts on it, or `None`
/// for a keyword that is not a field.
///
/// # Errors
///
/// Refuses a keyword this engine does not run, and a value it does not
/// read the way Suricata does.
pub fn compile(keyword: &'static str, argument: &str) -> Compiled<(&'static str, FieldCheck)> {
    let arg = argument.trim();
    Ok(match keyword {
        "dns.opcode" | "dns.rcode" | "dns.rrtype" | "tls.cert_chain_len" => {
            let max = match keyword {
                "dns.opcode" | "dns.rcode" => u64::from(u8::MAX),
                "dns.rrtype" => u64::from(u16::MAX),
                _ => u64::from(u32::MAX),
            };
            let condition = IntMatch::parse(arg, max).map_err(|e| refused(keyword, e))?;
            (keyword, FieldCheck::Int(condition))
        }
        "tls.version" => ("tls.version", tls_version(arg)?),
        "ssl_version" => ("tls.version", ssl_version(arg)?),
        "ssl_state" => ("ssl_state", ssl_state(arg)?),
        "tls_cert_notbefore" | "tls_cert_notafter" => {
            let (order, date) = match arg.as_bytes().first() {
                Some(b'<') => (std::cmp::Ordering::Less, &arg[1..]),
                Some(b'>') => (std::cmp::Ordering::Greater, &arg[1..]),
                _ => (std::cmp::Ordering::Equal, arg),
            };
            let secs = date_secs(date.trim()).ok_or_else(|| {
                refused(keyword, format!("'{arg}' is not a date this engine reads"))
            })?;
            (keyword, FieldCheck::Date(order, secs))
        }
        "tls_cert_expired" => ("tls_cert_notafter", FieldCheck::Expired),
        "tls_cert_valid" => ("tls_cert_notafter", FieldCheck::Valid),
        "tls.subject" | "tls.issuerdn" => {
            let (negated, quoted) = arg
                .strip_prefix('!')
                .map_or((false, arg), |rest| (true, rest.trim_start()));
            let field = if keyword == "tls.subject" {
                "tls.cert_subject"
            } else {
                "tls.cert_issuer"
            };
            let text = unquote(quoted).to_string();
            (field, FieldCheck::Contains { text, negated })
        }
        "tls.fingerprint" => (
            "tls.cert_fingerprint",
            FieldCheck::Equals(unquote(arg).to_string()),
        ),
        "dcerpc.iface" => ("dcerpc.iface", iface(arg)?),
        "dcerpc.opnum" => ("dcerpc.opnum", opnums(arg)?),
        other => return Err(refused(other, "is not run by the inspection engine")),
    })
}

/// A UUID, then `any_frag` (which changes nothing: every fragment is
/// read alike) or a condition on the major version.
fn iface(arg: &str) -> Compiled<FieldCheck> {
    let mut parts = arg.split(',').map(str::trim);
    let text = parts.next().unwrap_or_default();
    let uuid =
        uuid_of(text).ok_or_else(|| refused("dcerpc.iface", format!("'{text}' is not a UUID")))?;
    let mut version = None;
    for part in parts.filter(|p| *p != "any_frag") {
        let (op, rest) = match part.as_bytes().first() {
            Some(b'<') => (IntOp::Lt, &part[1..]),
            Some(b'>') => (IntOp::Gt, &part[1..]),
            Some(b'=') => (IntOp::Eq, &part[1..]),
            Some(b'!') => (IntOp::Ne, &part[1..]),
            _ => (IntOp::Eq, part),
        };
        let a = number(rest.trim()).map_err(|e| refused("dcerpc.iface", e))?;
        if a > u64::from(u16::MAX) {
            return Err(refused("dcerpc.iface", format!("'{part}' is above 65535")));
        }
        version = Some(IntMatch { op, a, b: 0 });
    }
    Ok(FieldCheck::Iface { uuid, version })
}

/// Operation numbers and inclusive ranges of them, comma separated.
fn opnums(arg: &str) -> Compiled<FieldCheck> {
    let mut ranges = Vec::new();
    for part in arg.split(',').map(str::trim) {
        let bad = |e: String| refused("dcerpc.opnum", e);
        let (low, high) = part.split_once('-').unwrap_or((part, part));
        let range = (
            number(low.trim()).map_err(bad)?,
            number(high.trim()).map_err(bad)?,
        );
        ranges.push(range);
    }
    Ok(FieldCheck::Ranges(ranges))
}

fn unquote(text: &str) -> &str {
    text.strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .unwrap_or(text)
}

fn tls_version(arg: &str) -> Compiled<FieldCheck> {
    let (negated, word) = arg
        .strip_prefix('!')
        .map_or((false, arg), |rest| (true, rest.trim()));
    let version = match word {
        "1.0" => 0x0301,
        "1.1" => 0x0302,
        "1.2" => 0x0303,
        "1.3" => 0x0304,
        "2.0" | "ssl2" => 0x0200,
        "3.0" | "ssl3" => 0x0300,
        other => number(other).map_err(|e| refused("tls.version", e))?,
    };
    Ok(if negated {
        FieldCheck::Version {
            any: Vec::new(),
            none: vec![version],
        }
    } else {
        FieldCheck::Version {
            any: vec![version],
            none: Vec::new(),
        }
    })
}

fn ssl_version(arg: &str) -> Compiled<FieldCheck> {
    let mut any = Vec::new();
    let mut none = Vec::new();
    for word in arg.split(',').map(str::trim).filter(|w| !w.is_empty()) {
        let (negated, name) = word
            .strip_prefix('!')
            .map_or((false, word), |rest| (true, rest.trim()));
        let version = match name {
            "sslv2" => 0x0200,
            "sslv3" => 0x0300,
            "tls1.0" => 0x0301,
            "tls1.1" => 0x0302,
            "tls1.2" => 0x0303,
            "tls1.3" => 0x0304,
            other => {
                return Err(refused(
                    "ssl_version",
                    format!("'{other}' is not an SSL version"),
                ));
            }
        };
        if negated {
            none.push(version);
        } else {
            any.push(version);
        }
    }
    Ok(FieldCheck::Version { any, none })
}

fn ssl_state(arg: &str) -> Compiled<FieldCheck> {
    let mut any = 0;
    let mut none = 0;
    for word in arg.split([',', '|']).map(str::trim) {
        let (negated, name) = word
            .strip_prefix('!')
            .map_or((false, word), |rest| (true, rest.trim()));
        let flag = match name {
            "client_hello" => STATE_CLIENT_HELLO,
            "server_hello" => STATE_SERVER_HELLO,
            other => {
                return Err(refused(
                    "ssl_state",
                    format!(
                        "'{other}' is not yet followed: the key exchange states are not read the way Suricata moves them"
                    ),
                ));
            }
        };
        if negated {
            none |= flag;
        } else {
            any |= flag;
        }
    }
    Ok(FieldCheck::State { any, none })
}

/// The second a date `YYYY[-MM[-DD[THH[:MM[:SS]]]]]` names, in UTC.
fn date_secs(date: &str) -> Option<u64> {
    let (day, time) = date.split_once('T').unwrap_or((date, ""));
    let mut d = day.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: i64 = d.next().map_or(Ok(1), str::parse).ok()?;
    let mday: i64 = d.next().map_or(Ok(1), str::parse).ok()?;
    if d.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&mday) {
        return None;
    }
    let mut t = time.split(':').filter(|s| !s.is_empty());
    let hour: i64 = t.next().map_or(Ok(0), str::parse).ok()?;
    let minute: i64 = t.next().map_or(Ok(0), str::parse).ok()?;
    let second: i64 = t.next().map_or(Ok(0), str::parse).ok()?;
    if t.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    // Days from the civil date, the proleptic Gregorian calendar.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + mday - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second).ok()
}

impl FieldCheck {
    /// Whether the condition holds on the field `name` of `fields`, `now`
    /// being the packet's time in seconds.
    #[must_use]
    pub fn holds(&self, name: &str, fields: &Fields, now: u64) -> bool {
        let int = |field: &str| fields.get(field, 0).and_then(int_of);
        match self {
            Self::Int(condition) => (0..)
                .map_while(|i| fields.get(name, i))
                .filter_map(int_of)
                .any(|v| condition.matches(v)),
            Self::State { any, none } => {
                let v = int(name).unwrap_or(0);
                (*any == 0 || v & any != 0) && v & none == 0
            }
            Self::Version { any, none } => int(name).is_some_and(|v| {
                v != 0 && (any.is_empty() || any.contains(&v)) && !none.contains(&v)
            }),
            Self::Date(order, secs) => int(name).is_some_and(|v| v.cmp(secs) == *order),
            Self::Expired => int("tls_cert_notafter").is_some_and(|after| now > after),
            Self::Valid => match (int("tls_cert_notbefore"), int("tls_cert_notafter")) {
                (Some(before), Some(after)) => before <= now && now <= after,
                _ => false,
            },
            Self::Contains { text, negated } => fields.get(name, 0).is_some_and(|value| {
                let found = memchr::memmem::find(value, text.as_bytes()).is_some();
                found != *negated
            }),
            Self::Equals(text) => fields
                .get(name, 0)
                .is_some_and(|value| value.eq_ignore_ascii_case(text.as_bytes())),
            Self::Iface { uuid, version } => fields.get(name, 0).is_some_and(|value| {
                value.get(..16) == Some(&uuid[..])
                    && version.is_none_or(|condition| {
                        value.get(16..18).is_some_and(|v| {
                            condition.matches(u64::from(u16::from_be_bytes([v[0], v[1]])))
                        })
                    })
            }),
            Self::Ranges(ranges) => {
                int(name).is_some_and(|v| ranges.iter().any(|&(low, high)| low <= v && v <= high))
            }
        }
    }

    /// Whether the condition reads the packet's time.
    #[must_use]
    pub const fn reads_time(&self) -> bool {
        matches!(self, Self::Expired | Self::Valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_interface_matches_its_uuid_and_major_version() {
        let mut f = Fields::default();
        let mut value = uuid_of("4b324fc8-1670-01d3-1278-5a47bf6ee188")
            .unwrap()
            .to_vec();
        value.extend_from_slice(&[0, 3, 0, 0]);
        f.put("dcerpc.iface", value);
        let check = |arg: &str| {
            let (name, check) = compile("dcerpc.iface", arg).unwrap();
            check.holds(name, &f, 0)
        };
        assert!(check("4b324fc8-1670-01d3-1278-5a47bf6ee188"));
        assert!(check("4B324FC8-1670-01D3-1278-5A47BF6EE188,any_frag"));
        assert!(check("4b324fc8-1670-01d3-1278-5a47bf6ee188,=3"));
        assert!(!check("4b324fc8-1670-01d3-1278-5a47bf6ee188,>3"));
        assert!(check("4b324fc8-1670-01d3-1278-5a47bf6ee188,!2,any_frag"));
        assert!(!check("12345778-1234-abcd-ef00-0123456789ac"));
        assert!(compile("dcerpc.iface", "not-a-uuid").is_err());
    }

    #[test]
    fn the_operation_number_matches_a_list_or_a_range() {
        let mut f = Fields::default();
        f.put_int("dcerpc.opnum", 31);
        let check = |arg: &str| {
            let (name, check) = compile("dcerpc.opnum", arg).unwrap();
            check.holds(name, &f, 0)
        };
        assert!(check("31"));
        assert!(check("5,31"));
        assert!(check("30-32"));
        assert!(!check("7"));
        assert!(!Fields::default().has("dcerpc.opnum"));
    }

    #[test]
    fn dates_are_read_to_the_second() {
        assert_eq!(date_secs("1970"), Some(0));
        assert_eq!(date_secs("2000-01-01"), Some(946_684_800));
        assert_eq!(date_secs("2024-02-29T12:30:15"), Some(1_709_209_815));
        assert_eq!(date_secs("2024-13"), None);
        assert_eq!(date_secs("x"), None);
    }

    #[test]
    fn the_handshake_state_matches_one_of_or_none_of() {
        let mut f = Fields::default();
        f.put_int("ssl_state", STATE_SERVER_HELLO);
        let check = |arg: &str| {
            compile("ssl_state", arg)
                .unwrap()
                .1
                .holds("ssl_state", &f, 0)
        };
        assert!(check("server_hello"));
        assert!(check("client_hello|server_hello"));
        assert!(!check("client_hello"));
        assert!(check("!client_hello"));
        assert!(!check("!server_hello"));
        assert!(compile("ssl_state", "client_keyx").is_err());
    }

    #[test]
    fn an_unknown_version_matches_nothing_even_negated() {
        let f = Fields::default();
        let check = |k: &'static str, arg: &str| {
            let (name, c) = compile(k, arg).unwrap();
            c.holds(name, &f, 0)
        };
        assert!(!check("ssl_version", "!tls1.2"));
        assert!(!check("tls.version", "!1.2"));
        let mut g = Fields::default();
        g.put_int("tls.version", 0x0301);
        let (name, c) = compile("ssl_version", "tls1.0,tls1.3").unwrap();
        assert!(c.holds(name, &g, 0));
        let (name, c) = compile("tls.version", "0x0301").unwrap();
        assert!(c.holds(name, &g, 0));
    }

    #[test]
    fn validity_is_read_at_the_packet_time() {
        let mut f = Fields::default();
        f.put_int("tls_cert_notbefore", 100);
        f.put_int("tls_cert_notafter", 200);
        let (name, valid) = compile("tls_cert_valid", "").unwrap();
        let (_, expired) = compile("tls_cert_expired", "").unwrap();
        assert!(valid.holds(name, &f, 150) && !expired.holds(name, &f, 150));
        assert!(!valid.holds(name, &f, 250) && expired.holds(name, &f, 250));
    }

    #[test]
    fn legacy_subject_and_fingerprint() {
        let mut f = Fields::default();
        f.put("tls.cert_subject", b"CN=leaf".to_vec());
        f.put("tls.cert_fingerprint", b"ab:cd".to_vec());
        let check = |k: &'static str, arg: &str| {
            let (name, c) = compile(k, arg).unwrap();
            c.holds(name, &f, 0)
        };
        assert!(check("tls.subject", "\"CN=leaf\""));
        assert!(check("tls.subject", "!\"CN=nope\""));
        assert!(!check("tls.subject", "!\"CN\""));
        assert!(!check("tls.issuerdn", "!\"CN\""));
        assert!(check("tls.fingerprint", "\"AB:CD\""));
    }
}

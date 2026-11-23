//! The request URI as Suricata's `http.uri` reads it: the path decoded,
//! its UTF-8 folded to bytes (`?` above U+00FF) and its dot segments removed, then the query
//! and the fragment decoded, all with the defaults of Suricata's IDS
//! personality. The scheme and the authority of an absolute URI are left
//! out, as Suricata leaves them out unless told to keep them.

/// The parts of a request URI, as they stand on the wire.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parts<'a> {
    pub scheme: Option<&'a [u8]>,
    pub hostname: Option<&'a [u8]>,
    pub port: Option<&'a [u8]>,
    pub path: Option<&'a [u8]>,
    pub query: Option<&'a [u8]>,
    pub fragment: Option<&'a [u8]>,
}

fn find(hay: &[u8], needle: u8) -> Option<usize> {
    hay.iter().position(|&b| b == needle)
}

/// Split a request URI. Text not starting with `/` and holding a `:`
/// carries a scheme, and an authority after it when `//` follows.
#[must_use]
pub fn split(uri: &[u8]) -> Parts<'_> {
    let mut parts = Parts::default();
    let mut rest = uri;
    if !rest.starts_with(b"/")
        && let Some(colon) = find(rest, b':')
    {
        parts.scheme = Some(&rest[..colon]);
        rest = &rest[colon + 1..];
        if rest.starts_with(b"//")
            && !rest[2..].starts_with(b"/")
            && let Some(at) = find(&rest[2..], b'@')
        {
            rest = &rest[2 + at + 1..];
        }
        let mut host = rest.strip_prefix(b"//").unwrap_or(rest);
        if !host.starts_with(b"/") {
            while let Some(stripped) = host.strip_prefix(b" ") {
                host = stripped;
            }
            let end = if host.starts_with(b"[") {
                host.iter().position(|&b| b == b']').map_or_else(
                    || {
                        host.iter()
                            .position(|&b| b"/?#".contains(&b))
                            .unwrap_or(host.len())
                    },
                    |close| close + 1,
                )
            } else {
                host.iter()
                    .position(|&b| b"/?#:".contains(&b))
                    .unwrap_or(host.len())
            };
            if end > 0 {
                let mut name = &host[..end];
                while let Some(trimmed) = name.strip_suffix(b" ") {
                    name = trimmed;
                }
                parts.hostname = Some(name);
                rest = &host[end..];
                if let Some(after) = rest.strip_prefix(b":") {
                    let stop = after
                        .iter()
                        .position(|&b| b"/?#".contains(&b))
                        .unwrap_or(after.len());
                    let port = after[..stop].trim_ascii();
                    if !port.is_empty() {
                        parts.port = Some(port);
                    }
                    rest = &after[stop..];
                }
            }
        }
    }
    let stop = rest
        .iter()
        .position(|&b| b == b'?' || b == b'#')
        .unwrap_or(rest.len());
    if stop > 0 {
        parts.path = Some(&rest[..stop]);
    }
    rest = &rest[stop..];
    if let Some(after) = rest.strip_prefix(b"?") {
        let stop = find(after, b'#').unwrap_or(after.len());
        parts.query = Some(&after[..stop]);
        rest = &after[stop..];
    }
    if let Some(after) = rest.strip_prefix(b"#") {
        parts.fragment = Some(after);
    }
    parts
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// The byte a character stands for: itself below U+0100, `?` above, as
/// Suricata's defaults read it (no best-fit folding).
fn narrow(codepoint: u32) -> u8 {
    u8::try_from(codepoint).unwrap_or(b'?')
}

/// Decode a `%` escape at the head of `rest` (the `%` already taken):
/// the byte it stands for and how many bytes it used, `None` when it is
/// no valid escape and the `%` stands for itself.
fn escape(rest: &[u8]) -> Option<(u8, usize)> {
    match rest {
        [b'u' | b'U', a, b, c, d, ..] => {
            let digits = [hex(*a)?, hex(*b)?, hex(*c)?, hex(*d)?];
            let high = (digits[0] << 4) | digits[1];
            let low = (digits[2] << 4) | digits[3];
            let byte = if high == 0 {
                low
            } else {
                narrow((u32::from(high) << 8) | u32::from(low))
            };
            Some((byte, 5))
        }
        [b'u' | b'U', ..] => None,
        [a, b, ..] => Some(((hex(*a)? << 4) | hex(*b)?, 2)),
        _ => None,
    }
}

/// The query and the fragment: escapes decoded, nothing else.
#[must_use]
pub fn decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while let Some(&b) = input.get(i) {
        i += 1;
        if b == b'%'
            && let Some((byte, used)) = escape(&input[i..])
        {
            out.push(byte);
            i += used;
        } else {
            out.push(b);
        }
    }
    out
}

/// The path's first pass: escapes decoded, backslashes read as slashes,
/// runs of slashes kept as one.
fn decode_path(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0;
    while let Some(&b) = input.get(i) {
        i += 1;
        let mut byte = b;
        if b == b'%'
            && let Some((decoded, used)) = escape(&input[i..])
        {
            byte = decoded;
            i += used;
        }
        if byte == b'\\' {
            byte = b'/';
        }
        if byte == b'/' && out.last() == Some(&b'/') {
            continue;
        }
        out.push(byte);
    }
    out
}

/// The path's UTF-8 read as characters, each folded to one byte; a broken
/// sequence is one `?`, and a sequence cut short at the end loses its
/// first byte.
fn fold_utf8(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while let Some(&lead) = input.get(i) {
        let (len, mut codepoint) = match lead {
            0x00..=0x7f => {
                out.push(lead);
                i += 1;
                continue;
            }
            0xc0..=0xdf => (2, u32::from(lead & 0x1f)),
            0xe0..=0xef => (3, u32::from(lead & 0x0f)),
            0xf0..=0xf7 => (4, u32::from(lead & 0x07)),
            _ => {
                out.push(b'?');
                i += 1;
                continue;
            }
        };
        let mut taken = 1;
        let mut broken = false;
        while taken < len {
            match input.get(i + taken) {
                Some(&next) if next & 0xc0 == 0x80 => {
                    codepoint = (codepoint << 6) | u32::from(next & 0x3f);
                    taken += 1;
                }
                Some(_) => {
                    broken = true;
                    break;
                }
                None => break,
            }
        }
        if broken {
            out.push(b'?');
            i += taken;
        } else if taken < len {
            out.extend(std::iter::repeat_n(b'?', taken - 1));
            i += taken;
        } else {
            out.push(narrow(codepoint));
            i += len;
        }
    }
    out
}

/// What the dot-segment walk holds back while it cannot yet tell whether
/// the bytes are a segment of their own.
#[derive(Clone, Copy)]
enum Held {
    /// Nothing written yet, nothing held.
    Start,
    /// `.` or `..` at the very start.
    Leading(u8),
    /// A `/`, written only if a segment follows or the path ends on it.
    /// `false` when it closed a `.` or `..` segment, and then the path
    /// ending there adds nothing.
    Slash(bool),
    /// `/.` or `/..`.
    SlashDots(u8),
    /// Inside an ordinary segment.
    Segment,
}

/// Drop the last written segment and the slash before it.
fn pop_segment(out: &mut Vec<u8>) {
    let cut = out.iter().rposition(|&b| b == b'/').unwrap_or(0);
    out.truncate(cut);
}

/// Dot-segment removal (RFC 3986 section 5.2.4) as Suricata walks it: a
/// path ending on a removed segment keeps no trailing slash, and `/.` or
/// `/..` alone leave nothing.
fn remove_dots(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut held = Held::Start;
    for &c in input {
        held = match (held, c) {
            (Held::Start, b'.') => Held::Leading(1),
            (Held::Start | Held::Segment, b'/') => Held::Slash(true),
            (Held::Leading(1), b'.') => Held::Leading(2),
            (Held::Leading(_), b'/') => Held::Start,
            (Held::Slash(_), b'.') => Held::SlashDots(1),
            (Held::SlashDots(1), b'/') => Held::Slash(false),
            (Held::SlashDots(1), b'.') => Held::SlashDots(2),
            (Held::SlashDots(_), b'/') => {
                pop_segment(&mut out);
                Held::Slash(false)
            }
            (Held::Segment, _) => {
                out.push(c);
                Held::Segment
            }
            (prefix, _) => {
                match prefix {
                    Held::Leading(dots) => out.extend(std::iter::repeat_n(b'.', usize::from(dots))),
                    Held::Slash(_) => out.push(b'/'),
                    Held::SlashDots(dots) => {
                        out.push(b'/');
                        out.extend(std::iter::repeat_n(b'.', usize::from(dots)));
                    }
                    Held::Start | Held::Segment => {}
                }
                out.push(c);
                Held::Segment
            }
        };
    }
    match held {
        Held::Slash(true) => out.push(b'/'),
        Held::SlashDots(2) => pop_segment(&mut out),
        _ => {}
    }
    out
}

/// The path as `http.uri` holds it.
#[must_use]
pub fn normalize_path(path: &[u8]) -> Vec<u8> {
    remove_dots(&fold_utf8(&decode_path(path)))
}

/// `http.uri`: the normalized path, then the decoded query and fragment.
#[must_use]
pub fn normalized(uri: &[u8]) -> Vec<u8> {
    let parts = split(uri);
    let mut out = parts.path.map_or_default(normalize_path);
    if let Some(query) = parts.query {
        out.push(b'?');
        out.extend(decode(query));
    }
    if let Some(fragment) = parts.fragment {
        out.push(b'#');
        out.extend(decode(fragment));
    }
    out
}

/// The host an absolute URI names, as `http.host` holds it: decoded,
/// lowercased, trailing dots dropped.
#[must_use]
pub fn uri_host(uri: &[u8]) -> Option<Vec<u8>> {
    let mut host = decode(split(uri).hostname?);
    host.make_ascii_lowercase();
    while host.last() == Some(&b'.') {
        host.pop();
    }
    Some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(uri: &str) -> Vec<u8> {
        normalized(uri.as_bytes())
    }

    #[test]
    fn dot_segments_go_as_suricata_drops_them() {
        assert_eq!(n("/a/./b"), b"/a/b");
        assert_eq!(n("/a/b/../c"), b"/a/c");
        assert_eq!(n("/a/./"), b"/a");
        assert_eq!(n("/a/b/../"), b"/a");
        assert_eq!(n("/a/../"), b"");
        assert_eq!(n("/a/b/.."), b"/a");
        assert_eq!(n("/a/..."), b"/a/...");
        assert_eq!(n("/a/.b"), b"/a/.b");
        assert_eq!(n("./a"), b"a");
        assert_eq!(n("/a/"), b"/a/");
        assert_eq!(n("/."), b"");
        assert_eq!(n("/.."), b"");
        assert_eq!(n("/../../etc/passwd"), b"/etc/passwd");
    }

    #[test]
    fn escapes_backslashes_and_slashes() {
        assert_eq!(n("/a%2fb"), b"/a/b");
        assert_eq!(n("/a%5cb"), b"/a/b");
        assert_eq!(n("/a\\b"), b"/a/b");
        assert_eq!(n("//a///b"), b"/a/b");
        assert_eq!(n("/a%zz"), b"/a%zz");
        assert_eq!(n("/a%"), b"/a%");
        assert_eq!(n("/a%u12"), b"/a%u12");
        assert_eq!(n("/a%00b"), b"/a\0b");
        assert_eq!(n("/A+B"), b"/A+B");
    }

    #[test]
    fn characters_above_a_byte_fold_as_suricata_folds_them() {
        assert_eq!(n("/%c3%a9"), b"/\xe9");
        assert_eq!(n("/%u1234"), b"/?");
        assert_eq!(n("/%u017a%uff21"), b"/??");
        assert_eq!(n("/%c5%ba"), b"/?");
        assert_eq!(n("/%C0%AF"), b"//");
        assert_eq!(n("/\u{e9}"), b"/\xe9");
        assert_eq!(normalized(b"/\xe9"), b"/");
        assert_eq!(normalized(b"/\xe9A"), b"/?A");
        assert_eq!(normalized(b"/\x80"), b"/?");
    }

    #[test]
    fn query_and_fragment_are_decoded_only() {
        assert_eq!(n("/a/../b?x=%41/../&y=%u0042#%43"), b"/b?x=A/../&y=B#C");
        assert_eq!(n("?q"), b"?q");
    }

    #[test]
    fn an_absolute_uri_keeps_its_path_and_names_its_host() {
        assert_eq!(n("http://Ex.COM:8080/a?b"), b"/a?b");
        assert_eq!(n("http://ex.com"), b"");
        assert_eq!(
            uri_host(b"http://user:pw@Ex.COM.:8080/a"),
            Some(b"ex.com".to_vec())
        );
        assert_eq!(uri_host(b"/a"), None);
        assert_eq!(n("*"), b"*");
    }
}

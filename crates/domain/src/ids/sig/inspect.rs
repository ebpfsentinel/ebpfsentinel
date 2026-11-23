//! A signature's matches run over the bytes they inspect, the way Suricata
//! walks them: a cursor that a match moves, windows placed from the start of
//! the buffer or from the cursor, and a return to an earlier content or pcre
//! to try its next occurrence when something after it fails.
//!
//! Each behaviour below is held to a real Suricata by
//! `tests/fixtures/suricata/inspect-verdicts.txt`, which records what that
//! engine decided on every case of `inspect.cases`.

use std::borrow::Cow;
use std::cell::OnceCell;
use std::collections::HashMap;

use md5::Md5;
use pcre2::bytes::{Regex as Pcre2, RegexBuilder};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::int::{IntMatch, IntOp};
use super::model::{
    Base64Decode, Buffer, ByteOp, ByteRead, Check, Content, Endian, FastPattern, FloatMatch,
    HeaderField, Match, MathOp, NumBase, Pcre, Signature, Transform, Value,
};
use crate::ids::flow::State;
use crate::ids::suricata::{Compiled, Refused};

/// How many times one inspection may return to an earlier match to try its
/// next occurrence, Suricata's default `inspection-recursion-limit`.
const RETRY_BUDGET: u32 = 3000;

/// A signature's matches, ready to run over a packet.
#[derive(Debug)]
pub struct Program {
    lists: Vec<List>,
    dsize: Vec<IntMatch>,
    slots: usize,
    fast: Option<Needle>,
    state: Option<State>,
}

/// Bytes every payload the program matches holds somewhere, so a payload
/// without them is not worth running the program on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Needle {
    pub bytes: Vec<u8>,
    /// Whether ASCII letters match in either case.
    pub nocase: bool,
}

#[derive(Debug)]
struct List {
    source: Source,
    transforms: Vec<Xform>,
    ops: Vec<Op>,
    /// Whether any op after this one reads the cursor: only then is it worth
    /// trying the next occurrence of a content or pcre when the rest fails.
    cursor_after: Vec<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Payload,
    Decoded,
    Sticky(&'static str),
}

/// A number written in the rule, or the variable an earlier match set.
#[derive(Debug, Clone, Copy)]
enum Num {
    Lit(i64),
    Slot(usize),
}

// The four flags are Suricata's own content modifiers.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug)]
struct ContentOp {
    bytes: Vec<u8>,
    negated: bool,
    nocase: bool,
    offset: Option<Num>,
    depth: Option<Num>,
    distance: Option<Num>,
    within: Option<Num>,
    startswith: bool,
    endswith: bool,
}

impl ContentOp {
    const fn relative(&self) -> bool {
        self.distance.is_some() || self.within.is_some()
    }
}

#[derive(Debug)]
struct PcreOp {
    regex: Pcre2,
    relative: bool,
    negated: bool,
    anchored: bool,
}

#[derive(Debug)]
struct ReadOp {
    nbytes: Num,
    offset: Num,
    read: ByteRead,
}

#[derive(Debug)]
enum Op {
    Content(ContentOp),
    Pcre(PcreOp),
    IsDataAt {
        negated: bool,
        at: Num,
        relative: bool,
    },
    Bsize(IntMatch),
    ByteTest {
        at: ReadOp,
        negated: bool,
        op: ByteOp,
        value: Num,
    },
    ByteJump {
        at: ReadOp,
        multiplier: u64,
        align: bool,
        from_beginning: bool,
        from_end: bool,
        post_offset: i64,
    },
    ByteExtract {
        at: ReadOp,
        multiplier: u64,
        align: u64,
        slot: usize,
    },
    ByteMath {
        at: ReadOp,
        oper: MathOp,
        rvalue: Num,
        slot: usize,
    },
    Entropy {
        bytes: Option<u32>,
        offset: i64,
        value: FloatMatch,
    },
    Base64(Base64Decode),
}

impl Op {
    const fn reads_cursor(&self) -> bool {
        match self {
            Self::Content(c) => c.relative(),
            Self::Pcre(p) => p.relative,
            Self::IsDataAt { relative, .. } => *relative,
            Self::ByteTest { at, .. }
            | Self::ByteJump { at, .. }
            | Self::ByteExtract { at, .. }
            | Self::ByteMath { at, .. } => at.read.relative,
            Self::Base64(b) => b.relative,
            Self::Bsize(_) | Self::Entropy { .. } => false,
        }
    }
}

/// A transform that rewrites a buffer before its matches run.
#[derive(Debug)]
enum Xform {
    Lower,
    Upper,
    StripWhitespace,
    CompressWhitespace,
    UrlDecode,
    FromBase64 {
        offset: usize,
        bytes: Option<usize>,
        strict: bool,
    },
    Md5,
    Sha1,
    Sha256,
    Xor(Vec<u8>),
    Pcre(Pcre2),
    DotPrefix,
    HeaderLowercase,
    StripPseudoHeaders,
}

fn refused(keyword: impl Into<String>, reason: impl Into<String>) -> Refused {
    Refused::new(keyword, reason)
}

impl Program {
    /// Compile the matches of a parsed signature.
    ///
    /// # Errors
    ///
    /// Refuses a match this engine does not run, a variable read before a
    /// match sets it, and a pcre or transform argument PCRE2 rejects.
    pub fn compile(signature: &Signature) -> Compiled<Self> {
        let mut names: HashMap<String, usize> = HashMap::new();
        let mut lists = Vec::new();
        for list in &signature.lists {
            let source = match list.buffer {
                Buffer::Payload => Source::Payload,
                Buffer::Base64Data => Source::Decoded,
                Buffer::Sticky(name) => Source::Sticky(name),
            };
            let transforms = list
                .transforms
                .iter()
                .map(compile_transform)
                .collect::<Compiled<Vec<_>>>()?;
            check_case(&list.transforms, &list.matches)?;
            let mut ops = Vec::new();
            for m in &list.matches {
                ops.push(compile_match(m, &mut names)?);
            }
            let cursor_after = (0..ops.len())
                .map(|i| ops[i + 1..].iter().any(Op::reads_cursor))
                .collect();
            lists.push(List {
                source,
                transforms,
                ops,
                cursor_after,
            });
        }
        let dsize = signature
            .checks
            .iter()
            .filter_map(|check| match check {
                Check::Header(HeaderField::Dsize, m) => Some(*m),
                _ => None,
            })
            .collect();
        Ok(Self {
            lists,
            dsize,
            slots: names.len(),
            fast: fast_pattern(signature),
            state: State::compile(signature)?,
        })
    }

    /// What the rule reads and writes outside the packet, `None` when it
    /// touches nothing there.
    #[must_use]
    pub const fn state(&self) -> Option<&State> {
        self.state.as_ref()
    }

    /// The bytes a payload must hold for the program to match it: the
    /// content `fast_pattern` names, or the longest content, among those
    /// read from the untransformed payload. `None` when no content is read
    /// there, as for a rule of pcre alone.
    #[must_use]
    pub const fn fast_pattern(&self) -> Option<&Needle> {
        self.fast.as_ref()
    }

    /// Whether the signature's matches hold on this payload. A list that
    /// inspects a buffer other than the payload and its base64 decoding finds
    /// nothing, so its signature does not match.
    #[must_use]
    pub fn matches(&self, payload: &[u8]) -> bool {
        self.matches_with(payload, &|_| None)
    }

    /// Whether the signature's matches hold, `sticky` handing the bytes of a
    /// named buffer when the packet has it.
    #[must_use]
    pub fn matches_with<'a>(
        &self,
        payload: &'a [u8],
        sticky: &'a dyn Fn(&str) -> Option<&'a [u8]>,
    ) -> bool {
        if !self.dsize.iter().all(|m| m.matches(len_u64(payload.len()))) {
            return false;
        }
        let mut run = Run {
            payload,
            sticky,
            slots: vec![0; self.slots],
            decoded: None,
            budget: RETRY_BUDGET,
        };
        self.list(0, &mut run)
    }

    /// Whether the program inspects a buffer other than the payload and its
    /// base64 decoding.
    #[must_use]
    pub fn sticky_buffers(&self) -> Vec<&'static str> {
        self.lists
            .iter()
            .filter_map(|l| match l.source {
                Source::Sticky(name) => Some(name),
                _ => None,
            })
            .collect()
    }

    fn list(&self, index: usize, run: &mut Run<'_>) -> bool {
        let Some(list) = self.lists.get(index) else {
            return true;
        };
        let raw: Cow<'_, [u8]> = match list.source {
            Source::Payload => Cow::Borrowed(run.payload),
            Source::Decoded => match &run.decoded {
                Some(bytes) => Cow::Owned(bytes.clone()),
                None => return false,
            },
            Source::Sticky(name) => match (run.sticky)(name) {
                Some(bytes) => Cow::Borrowed(bytes),
                None => return false,
            },
        };
        let mut bytes = raw;
        for xform in &list.transforms {
            bytes = Cow::Owned(apply(xform, &bytes));
        }
        let buf = Buf {
            bytes: &bytes,
            lower: OnceCell::new(),
        };
        self.step(index, 0, 0, &buf, run)
    }

    #[allow(clippy::too_many_lines)]
    fn step(&self, li: usize, oi: usize, cursor: usize, buf: &Buf<'_>, run: &mut Run<'_>) -> bool {
        let list = &self.lists[li];
        let Some(op) = list.ops.get(oi) else {
            return self.list(li + 1, run);
        };
        let len = buf.bytes.len();
        let retry = list.cursor_after[oi];
        match op {
            Op::Content(c) => {
                let Some((start, end)) = window(c, cursor, len, run) else {
                    return c.negated && self.step(li, oi + 1, cursor, buf, run);
                };
                if c.negated {
                    return find_content(c, buf, start, start, end).is_none()
                        && self.step(li, oi + 1, cursor, buf, run);
                }
                let mut from = start;
                while let Some(at) = find_content(c, buf, start, from, end) {
                    if self.step(li, oi + 1, at + c.bytes.len(), buf, run) {
                        return true;
                    }
                    if !retry || !run.spend() {
                        return false;
                    }
                    from = at + 1;
                }
                false
            }
            Op::Pcre(p) => {
                let base = if p.relative { cursor.min(len) } else { 0 };
                let subject = &buf.bytes[base..];
                if p.negated {
                    return !matches!(p.regex.find(subject), Ok(Some(_)))
                        && self.step(li, oi + 1, cursor, buf, run);
                }
                let mut from = 0;
                loop {
                    let Ok(Some(found)) = p.regex.find_at(subject, from) else {
                        return false;
                    };
                    if self.step(li, oi + 1, base + found.end(), buf, run) {
                        return true;
                    }
                    if p.anchored || !retry || !run.spend() || found.start() >= subject.len() {
                        return false;
                    }
                    from = found.start() + 1;
                }
            }
            Op::IsDataAt {
                negated,
                at,
                relative,
            } => {
                let at = run.signed(*at);
                let present = if *relative {
                    at >= 0 && pos(cursor).saturating_add(at) <= pos(len)
                } else {
                    at >= 0 && at < pos(len)
                };
                present != *negated && self.step(li, oi + 1, cursor, buf, run)
            }
            Op::Bsize(m) => m.matches(len_u64(len)) && self.step(li, oi + 1, cursor, buf, run),
            Op::ByteTest {
                at,
                negated,
                op,
                value,
            } => {
                let Some((v, _)) = read_at(at, cursor, buf.bytes, run) else {
                    return false;
                };
                let rhs = run.unsigned(*value);
                let held = match op {
                    ByteOp::Lt => v < rhs,
                    ByteOp::Gt => v > rhs,
                    ByteOp::Eq => v == rhs,
                    ByteOp::Le => v <= rhs,
                    ByteOp::Ge => v >= rhs,
                    ByteOp::And => v & rhs != 0,
                    ByteOp::Xor => v ^ rhs != 0,
                };
                held != *negated && self.step(li, oi + 1, cursor, buf, run)
            }
            Op::ByteJump {
                at,
                multiplier,
                align,
                from_beginning,
                from_end,
                post_offset,
            } => {
                let Some((v, end)) = read_at(at, cursor, buf.bytes, run) else {
                    return false;
                };
                let mut v = v.saturating_mul(*multiplier);
                if *align {
                    v = v.saturating_add(3) & !3;
                }
                let v = i64::try_from(v).unwrap_or(i64::MAX);
                let target = if *from_beginning {
                    v
                } else if *from_end {
                    pos(len).saturating_add(v)
                } else {
                    pos(end).saturating_add(v)
                }
                .saturating_add(*post_offset);
                match usize::try_from(target) {
                    Ok(next) if next <= len => self.step(li, oi + 1, next, buf, run),
                    _ => false,
                }
            }
            Op::ByteExtract {
                at,
                multiplier,
                align,
                slot,
            } => {
                let Some((v, end)) = read_at(at, cursor, buf.bytes, run) else {
                    return false;
                };
                let mut v = v.saturating_mul(*multiplier);
                if *align > 1 {
                    v = v.div_ceil(*align).saturating_mul(*align);
                }
                run.slots[*slot] = v;
                self.step(li, oi + 1, end, buf, run)
            }
            Op::ByteMath {
                at,
                oper,
                rvalue,
                slot,
            } => {
                let Some((v, end)) = read_at(at, cursor, buf.bytes, run) else {
                    return false;
                };
                let r = run.unsigned(*rvalue);
                let result = match oper {
                    MathOp::Add => Some(v.wrapping_add(r)),
                    MathOp::Sub => Some(v.wrapping_sub(r)),
                    MathOp::Mul => Some(v.wrapping_mul(r)),
                    MathOp::Div => v.checked_div(r),
                    MathOp::Shl => Some(
                        u32::try_from(r)
                            .ok()
                            .and_then(|s| v.checked_shl(s))
                            .unwrap_or(0),
                    ),
                    MathOp::Shr => Some(
                        u32::try_from(r)
                            .ok()
                            .and_then(|s| v.checked_shr(s))
                            .unwrap_or(0),
                    ),
                };
                let Some(result) = result else {
                    return false;
                };
                run.slots[*slot] = result;
                self.step(li, oi + 1, end, buf, run)
            }
            Op::Entropy {
                bytes,
                offset,
                value,
            } => {
                let Ok(start) = usize::try_from(*offset) else {
                    return false;
                };
                if start > len {
                    return false;
                }
                let end = match bytes {
                    Some(n) => match usize::try_from(*n).ok().and_then(|n| start.checked_add(n)) {
                        Some(end) if end <= len => end,
                        _ => return false,
                    },
                    None => len,
                };
                float_matches(value, entropy(&buf.bytes[start..end]))
                    && self.step(li, oi + 1, cursor, buf, run)
            }
            Op::Base64(decode) => {
                let start = if decode.relative { cursor } else { 0 }
                    .saturating_add(usize::try_from(decode.offset).unwrap_or(usize::MAX));
                let input = buf.bytes.get(start..).unwrap_or_default();
                let input = match decode.bytes.and_then(|n| usize::try_from(n).ok()) {
                    Some(n) => &input[..n.min(input.len())],
                    None => input,
                };
                run.decoded = Some(base64(input, false));
                self.step(li, oi + 1, cursor, buf, run)
            }
        }
    }
}

struct Run<'a> {
    payload: &'a [u8],
    sticky: &'a dyn Fn(&str) -> Option<&'a [u8]>,
    slots: Vec<u64>,
    decoded: Option<Vec<u8>>,
    budget: u32,
}

impl Run<'_> {
    fn spend(&mut self) -> bool {
        if self.budget == 0 {
            return false;
        }
        self.budget -= 1;
        true
    }

    fn unsigned(&self, n: Num) -> u64 {
        match n {
            Num::Lit(v) => u64::try_from(v).unwrap_or(0),
            Num::Slot(s) => self.slots[s],
        }
    }

    fn signed(&self, n: Num) -> i64 {
        match n {
            Num::Lit(v) => v,
            Num::Slot(s) => i64::try_from(self.slots[s]).unwrap_or(i64::MAX),
        }
    }
}

struct Buf<'a> {
    bytes: &'a [u8],
    lower: OnceCell<Vec<u8>>,
}

fn pos(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The bytes a content may occupy: from the start of the buffer for an
/// absolute content, from the cursor for a relative one. `None` when the
/// window lies outside the buffer.
fn window(c: &ContentOp, cursor: usize, len: usize, run: &Run<'_>) -> Option<(usize, usize)> {
    let (base, span) = if c.relative() {
        let base = pos(cursor).saturating_add(c.distance.map_or(0, |d| run.signed(d)));
        (base, c.within.map(|w| run.signed(w)))
    } else {
        let offset = c.offset.map_or(0, |o| run.signed(o));
        if offset < 0 {
            return None;
        }
        (offset, c.depth.map(|d| run.signed(d)))
    };
    let end = match span {
        Some(span) if span < 0 => return None,
        Some(span) => base.saturating_add(span).min(pos(len)),
        None => pos(len),
    };
    let start = usize::try_from(base.max(0)).ok()?;
    let end = usize::try_from(end).ok()?;
    (start <= end).then_some((start, end))
}

/// The first place at or after `from` where the content occurs inside
/// `[start, end)` and meets its `startswith` and `endswith`.
fn find_content(
    c: &ContentOp,
    buf: &Buf<'_>,
    start: usize,
    from: usize,
    end: usize,
) -> Option<usize> {
    let hay = if c.nocase {
        buf.lower
            .get_or_init(|| buf.bytes.to_ascii_lowercase())
            .as_slice()
    } else {
        buf.bytes
    };
    let n = c.bytes.len();
    let mut from = from;
    loop {
        let region = hay.get(from..end)?;
        let at = from + memchr::memmem::find(region, &c.bytes)?;
        if c.startswith && at != start {
            return None;
        }
        if !c.endswith || at + n == buf.bytes.len() {
            return Some(at);
        }
        from = at + 1;
    }
}

/// The number a byte keyword reads, and where its bytes end.
fn read_at(at: &ReadOp, cursor: usize, bytes: &[u8], run: &Run<'_>) -> Option<(u64, usize)> {
    let base = if at.read.relative { pos(cursor) } else { 0 };
    let start = usize::try_from(base.checked_add(run.signed(at.offset))?).ok()?;
    let n = usize::try_from(run.signed(at.nbytes)).ok()?;
    let end = start.checked_add(n)?;
    let field = bytes.get(start..end)?;
    let mut v = if let Some(base) = at.read.string {
        let radix = match base {
            NumBase::Hex => 16,
            NumBase::Dec => 10,
            NumBase::Oct => 8,
        };
        let text = std::str::from_utf8(field).ok()?;
        if text.is_empty() || !text.chars().all(|ch| ch.is_digit(radix)) {
            return None;
        }
        u64::from_str_radix(text, radix).ok()?
    } else {
        if n > 8 {
            return None;
        }
        let fold = |acc: u64, b: &u8| (acc << 8) | u64::from(*b);
        match at.read.endian {
            Endian::Big => field.iter().fold(0, fold),
            Endian::Little | Endian::Dce => field.iter().rev().fold(0, fold),
        }
    };
    if let Some(mask) = at.read.bitmask {
        v = (v & mask) >> mask.trailing_zeros();
    }
    Some((v, end))
}

/// Shannon entropy of the bytes, in bits per byte.
fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in bytes {
        counts[usize::from(*b)] += 1;
    }
    let total = f64::from(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = f64::from(*c) / total;
            -p * p.log2()
        })
        .sum()
}

fn float_matches(m: &FloatMatch, v: f64) -> bool {
    const EPSILON: f64 = 1e-6;
    match m.op {
        IntOp::Eq => (v - m.value).abs() < EPSILON,
        IntOp::Ne => (v - m.value).abs() >= EPSILON,
        IntOp::Lt => v < m.value,
        IntOp::Le => v <= m.value + EPSILON,
        IntOp::Gt => v > m.value,
        IntOp::Ge => v + EPSILON >= m.value,
        IntOp::Range => v > m.value && v < m.high,
        IntOp::NotRange | IntOp::MaskEq | IntOp::MaskNe => false,
    }
}

fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Base64 decoding as Suricata's keywords do it: padding optional, a last
/// partial group decoded, the input ending at `=`. A character outside the
/// alphabet ends it too, or is skipped when `skip_invalid` (RFC 2045).
fn base64(input: &[u8], skip_invalid: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 2);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in input {
        if c == b'=' {
            break;
        }
        let Some(v) = sextet(c) else {
            if skip_invalid {
                continue;
            }
            break;
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap_or(0));
        }
    }
    out
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn hex_value(b: u8) -> Option<u8> {
    char::from(b)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

fn apply(xform: &Xform, input: &[u8]) -> Vec<u8> {
    match xform {
        Xform::Lower => input.to_ascii_lowercase(),
        Xform::Upper => input.to_ascii_uppercase(),
        Xform::StripWhitespace => input.iter().copied().filter(|b| !is_space(*b)).collect(),
        Xform::CompressWhitespace => {
            let mut out = Vec::with_capacity(input.len());
            for &b in input {
                if !(is_space(b) && out.last().is_some_and(|p: &u8| is_space(*p))) {
                    out.push(b);
                }
            }
            out
        }
        Xform::UrlDecode => {
            let mut out = Vec::with_capacity(input.len());
            let mut i = 0;
            while i < input.len() {
                match input[i] {
                    b'%' => {
                        let pair = input
                            .get(i + 1)
                            .and_then(|h| hex_value(*h))
                            .zip(input.get(i + 2).and_then(|l| hex_value(*l)));
                        if let Some((h, l)) = pair {
                            out.push((h << 4) | l);
                            i += 3;
                            continue;
                        }
                        out.push(b'%');
                    }
                    b'+' => out.push(b' '),
                    b => out.push(b),
                }
                i += 1;
            }
            out
        }
        Xform::FromBase64 {
            offset,
            bytes,
            strict,
        } => {
            let input = input.get(*offset..).unwrap_or_default();
            let input = bytes.map_or(input, |n| &input[..n.min(input.len())]);
            base64(input, !*strict)
        }
        Xform::Md5 => Md5::digest(input).to_vec(),
        Xform::Sha1 => Sha1::digest(input).to_vec(),
        Xform::Sha256 => Sha256::digest(input).to_vec(),
        Xform::Xor(key) => input
            .iter()
            .zip(key.iter().cycle())
            .map(|(b, k)| b ^ k)
            .collect(),
        Xform::Pcre(regex) => match regex.captures(input) {
            Ok(Some(caps)) => caps
                .get(1)
                .or_else(|| caps.get(0))
                .map_or_else(Vec::new, |m| m.as_bytes().to_vec()),
            _ => input.to_vec(),
        },
        Xform::DotPrefix => {
            let mut out = Vec::with_capacity(input.len() + 1);
            out.push(b'.');
            out.extend_from_slice(input);
            out
        }
        Xform::HeaderLowercase => {
            let mut out = Vec::with_capacity(input.len());
            for line in input.split_inclusive(|b| *b == b'\n') {
                let name_end = line.iter().position(|b| *b == b':').unwrap_or(line.len());
                out.extend(line[..name_end].iter().map(u8::to_ascii_lowercase));
                out.extend_from_slice(&line[name_end..]);
            }
            out
        }
        Xform::StripPseudoHeaders => input
            .split_inclusive(|b| *b == b'\n')
            .filter(|line| !line.starts_with(b":"))
            .flatten()
            .copied()
            .collect(),
    }
}

fn compile_transform(t: &Transform) -> Compiled<Xform> {
    let k = t.name.as_str();
    let arg = t.argument.as_deref().unwrap_or("").trim();
    Ok(match k {
        "to_lowercase" => Xform::Lower,
        "to_uppercase" => Xform::Upper,
        "strip_whitespace" => Xform::StripWhitespace,
        "compress_whitespace" => Xform::CompressWhitespace,
        "url_decode" => Xform::UrlDecode,
        "to_md5" => Xform::Md5,
        "to_sha1" => Xform::Sha1,
        "to_sha256" => Xform::Sha256,
        "dotprefix" => Xform::DotPrefix,
        "header_lowercase" => Xform::HeaderLowercase,
        "strip_pseudo_headers" => Xform::StripPseudoHeaders,
        "xor" => {
            let hex = arg.trim_matches('"');
            if hex.is_empty() || !hex.len().is_multiple_of(2) {
                return Err(refused(k, "has a key that is not whole hex bytes"));
            }
            let key = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                .collect::<Option<Vec<u8>>>()
                .ok_or_else(|| refused(k, "has a key that is not hex"))?;
            Xform::Xor(key)
        }
        "pcrexform" => Xform::Pcre(pcrexform(arg.trim_matches('"'))?),
        "from_base64" => {
            let (mut offset, mut bytes, mut strict) = (0, None, true);
            for part in arg.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                let (name, value) = part
                    .split_once(' ')
                    .map_or((part, ""), |(n, v)| (n, v.trim()));
                let number = || {
                    value
                        .parse::<usize>()
                        .map_err(|_| refused(k, format!("'{part}' is not a number")))
                };
                match name {
                    "offset" => offset = number()?,
                    "bytes" => bytes = Some(number()?),
                    "mode" => {
                        strict = match value {
                            "rfc4648" | "strict" => true,
                            "rfc2045" => false,
                            other => return Err(refused(k, format!("has no mode '{other}'"))),
                        }
                    }
                    other => return Err(refused(k, format!("'{other}' is not an option of it"))),
                }
            }
            Xform::FromBase64 {
                offset,
                bytes,
                strict,
            }
        }
        other => {
            return Err(refused(
                other,
                "is a transform the inspection engine does not run",
            ));
        }
    })
}

/// Suricata refuses a content that a case transform of its list makes
/// impossible: an upper-case byte after `to_lowercase`, a lower-case one after
/// `to_uppercase`.
fn check_case(transforms: &[Transform], matches: &[Match]) -> Compiled<()> {
    for t in transforms {
        let clash: fn(&u8) -> bool = match t.name.as_str() {
            "to_lowercase" => u8::is_ascii_uppercase,
            "to_uppercase" => u8::is_ascii_lowercase,
            _ => continue,
        };
        for m in matches {
            if let Match::Content(c) = m
                && !c.nocase
                && c.bytes.iter().any(clash)
            {
                return Err(refused(
                    t.name.clone(),
                    "is followed by a content its case can never match",
                ));
            }
        }
    }
    Ok(())
}

fn num(value: &Value, names: &HashMap<String, usize>, k: &str) -> Compiled<Num> {
    match value {
        Value::Lit(v) => Ok(Num::Lit(*v)),
        Value::Var(name) => names.get(name).map(|s| Num::Slot(*s)).ok_or_else(|| {
            refused(
                k,
                format!("reads '{name}' before a byte_extract or byte_math sets it"),
            )
        }),
    }
}

fn opt_num(
    value: Option<&Value>,
    names: &HashMap<String, usize>,
    k: &str,
) -> Compiled<Option<Num>> {
    value.map(|v| num(v, names, k)).transpose()
}

fn slot(names: &mut HashMap<String, usize>, name: &str) -> usize {
    let next = names.len();
    *names.entry(name.to_string()).or_insert(next)
}

fn compile_content(c: &Content, names: &HashMap<String, usize>) -> Compiled<ContentOp> {
    let k = "content";
    Ok(ContentOp {
        bytes: if c.nocase {
            c.bytes.to_ascii_lowercase()
        } else {
            c.bytes.clone()
        },
        negated: c.negated,
        nocase: c.nocase,
        offset: opt_num(c.offset.as_ref(), names, k)?,
        depth: opt_num(c.depth.as_ref(), names, k)?,
        distance: opt_num(c.distance.as_ref(), names, k)?,
        within: opt_num(c.within.as_ref(), names, k)?,
        startswith: c.startswith,
        endswith: c.endswith,
    })
}

/// The expression as PCRE2 runs it, Suricata's own flags written into it:
/// `A` anchors at the start of the subject, `E` lets `$` match only at the
/// very end, `G` makes quantifiers lazy.
fn pcre_expression(p: &Pcre) -> String {
    let flags = p.flags.as_str();
    let expression = p.expression.as_str();
    let mut verbs_end = 0;
    while expression[verbs_end..].starts_with("(*") {
        match expression[verbs_end..].find(')') {
            Some(close) => verbs_end += close + 1,
            None => break,
        }
    }
    let (verbs, body) = expression.split_at(verbs_end);
    let body = if flags.contains('E') && !flags.contains('m') {
        dollar_at_end(body)
    } else {
        body.to_string()
    };
    let mut out = String::with_capacity(expression.len() + 8);
    out.push_str(verbs);
    if flags.contains('A') {
        out.push_str("\\G");
    }
    if flags.contains('G') {
        out.push_str("(?U)");
    }
    out.push_str(&body);
    out
}

/// Every `$` outside a class and an escape, written `\z`.
fn dollar_at_end(body: &str) -> String {
    let mut out = String::with_capacity(body.len() + 4);
    let mut chars = body.chars().peekable();
    let mut class = false;
    let mut class_start = false;
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                out.push(ch);
                if let Some(next) = chars.next() {
                    out.push(next);
                }
                class_start = false;
                continue;
            }
            '[' if !class => {
                class = true;
                class_start = true;
                out.push(ch);
                if chars.peek() == Some(&'^') {
                    out.push('^');
                    chars.next();
                }
                continue;
            }
            ']' if class && !class_start => class = false,
            '$' if !class => {
                out.push_str("\\z");
                continue;
            }
            _ => {}
        }
        class_start = false;
        out.push(ch);
    }
    out
}

fn fast_pattern(signature: &Signature) -> Option<Needle> {
    let contents: Vec<&Content> = signature
        .lists
        .iter()
        .filter(|l| l.buffer == Buffer::Payload && l.transforms.is_empty())
        .flat_map(|l| l.matches.iter())
        .filter_map(|m| match m {
            Match::Content(c) if !c.negated && !c.bytes.is_empty() => Some(c),
            _ => None,
        })
        .collect();
    let chosen = contents
        .iter()
        .find(|c| c.fast_pattern.is_some())
        .or_else(|| contents.iter().rev().max_by_key(|c| c.bytes.len()))?;
    let bytes = match chosen.fast_pattern {
        Some(FastPattern::Slice { offset, length }) => {
            let start = usize::from(offset);
            start
                .checked_add(usize::from(length))
                .and_then(|end| chosen.bytes.get(start..end))
                .filter(|b| !b.is_empty())
                .unwrap_or(&chosen.bytes)
        }
        _ => &chosen.bytes,
    };
    Some(Needle {
        bytes: bytes.to_vec(),
        nocase: chosen.nocase,
    })
}

/// Whether PCRE2 compiles the expression with its flags.
pub(crate) fn check_pcre(p: &Pcre) -> Compiled<()> {
    compile_pcre(p).map(drop)
}

/// Whether PCRE2 compiles a `pcrexform` expression.
pub(crate) fn check_pcrexform(expression: &str) -> Compiled<()> {
    pcrexform(expression).map(drop)
}

fn pcrexform(expression: &str) -> Compiled<Pcre2> {
    RegexBuilder::new()
        .jit_if_available(true)
        .build(expression)
        .map_err(|e| refused("pcrexform", format!("is not a PCRE2 expression: {e}")))
}

fn compile_pcre(p: &Pcre) -> Compiled<PcreOp> {
    let flags = p.flags.as_str();
    let regex = RegexBuilder::new()
        .caseless(flags.contains('i'))
        .dotall(flags.contains('s'))
        .multi_line(flags.contains('m'))
        .extended(flags.contains('x'))
        .jit_if_available(true)
        .build(&pcre_expression(p))
        .map_err(|e| refused("pcre", format!("is not a PCRE2 expression: {e}")))?;
    Ok(PcreOp {
        regex,
        relative: p.relative,
        negated: p.negated,
        anchored: flags.contains('A'),
    })
}

fn read_op(
    nbytes: &Value,
    offset: Num,
    read: ByteRead,
    names: &HashMap<String, usize>,
    k: &str,
) -> Compiled<ReadOp> {
    Ok(ReadOp {
        nbytes: num(nbytes, names, k)?,
        offset,
        read,
    })
}

fn compile_match(m: &Match, names: &mut HashMap<String, usize>) -> Compiled<Op> {
    Ok(match m {
        Match::Content(c) => Op::Content(compile_content(c, names)?),
        Match::Pcre(p) => Op::Pcre(compile_pcre(p)?),
        Match::IsDataAt(d) => Op::IsDataAt {
            negated: d.negated,
            at: num(&d.at, names, "isdataat")?,
            relative: d.relative,
        },
        Match::Bsize(b) => Op::Bsize(*b),
        Match::ByteTest(t) => {
            let k = "byte_test";
            Op::ByteTest {
                at: read_op(&t.nbytes, num(&t.offset, names, k)?, t.read, names, k)?,
                negated: t.negated,
                op: t.op,
                value: num(&t.value, names, k)?,
            }
        }
        Match::ByteJump(j) => {
            let k = "byte_jump";
            Op::ByteJump {
                at: read_op(&j.nbytes, num(&j.offset, names, k)?, j.read, names, k)?,
                multiplier: u64::from(j.multiplier),
                align: j.align,
                from_beginning: j.from_beginning,
                from_end: j.from_end,
                post_offset: j.post_offset,
            }
        }
        Match::ByteExtract(e) => {
            let at = ReadOp {
                nbytes: Num::Lit(i64::from(e.nbytes)),
                offset: Num::Lit(e.offset),
                read: e.read,
            };
            Op::ByteExtract {
                at,
                multiplier: u64::from(e.multiplier),
                align: u64::from(e.align),
                slot: slot(names, &e.name),
            }
        }
        Match::ByteMath(b) => {
            let k = "byte_math";
            let at = read_op(&b.nbytes, Num::Lit(b.offset), b.read, names, k)?;
            let rvalue = num(&b.rvalue, names, k)?;
            Op::ByteMath {
                at,
                oper: b.oper,
                rvalue,
                slot: slot(names, &b.result),
            }
        }
        Match::Entropy(e) => Op::Entropy {
            bytes: e.bytes,
            offset: e.offset,
            value: e.value,
        },
        Match::Base64Decode(d) => Op::Base64(*d),
        Match::Asn1(_) => return Err(refused("asn1", "is not run by the inspection engine")),
        Match::Absent { .. } => {
            return Err(refused("absent", "is not run by the inspection engine"));
        }
        Match::Dataset(d) => {
            return Err(refused(
                d.keyword.clone(),
                "is not run by the inspection engine",
            ));
        }
        Match::Field { keyword, .. } => {
            return Err(refused(
                keyword.clone(),
                "is not run by the inspection engine",
            ));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn needle_of(options: &str) -> Option<Needle> {
        let text = format!("alert tcp any any -> any 80 (msg:\"t\"; {options} sid:1;)");
        let signature =
            super::super::parse_signature(&text, &crate::ids::suricata::SuricataVars::default())
                .expect("parses");
        Program::compile(&signature)
            .expect("compiles")
            .fast_pattern()
            .cloned()
    }

    #[test]
    fn the_fast_pattern_is_the_one_named_else_the_longest_content_read_as_is() {
        let n = needle_of(r#"content:"ab"; content:"long one"; content:"cd"; fast_pattern;"#)
            .expect("a needle");
        assert_eq!(n.bytes, b"cd");
        let n = needle_of(r#"content:"abcdefgh"; fast_pattern:2,3;"#).expect("a needle");
        assert_eq!(n.bytes, b"cde");
        let n = needle_of(r#"content:"ab"; content:"LONGER"; nocase; content:"!x";"#)
            .expect("a needle");
        assert_eq!((n.bytes.as_slice(), n.nocase), (b"LONGER".as_slice(), true));
        let n = needle_of(r#"content:!"a much longer one"; content:"ab";"#).expect("a needle");
        assert_eq!(n.bytes, b"ab");
        assert_eq!(needle_of(r#"pcre:"/ab+c/";"#), None);
        assert_eq!(needle_of(r#"http.uri; content:"/admin";"#), None);
    }

    fn xf(name: &str, arg: Option<&str>) -> Xform {
        compile_transform(&Transform {
            name: name.to_string(),
            argument: arg.map(str::to_string),
        })
        .unwrap()
    }

    #[test]
    fn transforms_rewrite_as_the_documentation_shows() {
        assert_eq!(apply(&xf("to_lowercase", None), b"AbC"), b"abc");
        assert_eq!(apply(&xf("to_uppercase", None), b"AbC"), b"ABC");
        assert_eq!(apply(&xf("strip_whitespace", None), b" a \tb\r\n"), b"ab");
        assert_eq!(apply(&xf("compress_whitespace", None), b"a \t b"), b"a b");
        assert_eq!(apply(&xf("url_decode", None), b"a%20b+c%zz%"), b"a b c%zz%");
        assert_eq!(
            apply(&xf("dotprefix", None), b"example.com"),
            b".example.com"
        );
        assert_eq!(apply(&xf("xor", Some("\"0102\"")), b"ab"), [0x60, 0x60]);
        assert_eq!(apply(&xf("from_base64", None), b"aGVsbG8="), b"hello");
        assert_eq!(apply(&xf("from_base64", Some("offset 1")), b"xaGk"), b"hi");
        assert_eq!(
            apply(&xf("from_base64", Some("mode rfc2045")), b"aG!Vs bG8"),
            b"hello"
        );
        assert_eq!(
            apply(&xf("pcrexform", Some("\"x(ab+)y\"")), b"-xabby-"),
            b"abb"
        );
        assert_eq!(
            apply(&xf("header_lowercase", None), b"Host: A\r\nX-Y: B\r\n"),
            b"host: A\r\nx-y: B\r\n"
        );
        assert_eq!(
            apply(&xf("strip_pseudo_headers", None), b":path: /\nhost: a\n"),
            b"host: a\n"
        );
        assert_eq!(apply(&xf("to_md5", None), b"abc").len(), 16);
        assert_eq!(apply(&xf("to_sha1", None), b"abc").len(), 20);
        assert_eq!(apply(&xf("to_sha256", None), b"abc").len(), 32);
    }

    #[test]
    fn dollar_is_rewritten_outside_classes_and_escapes_only() {
        assert_eq!(dollar_at_end("a$"), "a\\z");
        assert_eq!(dollar_at_end("a\\$[$]$"), "a\\$[$]\\z");
        assert_eq!(dollar_at_end("[]$]$"), "[]$]\\z");
    }

    #[test]
    fn entropy_is_shannon_in_bits() {
        assert!(entropy(b"aaaa").abs() < 1e-9);
        assert!((entropy(b"ab") - 1.0).abs() < 1e-9);
        assert!((entropy(b"abcd") - 2.0).abs() < 1e-9);
    }
}

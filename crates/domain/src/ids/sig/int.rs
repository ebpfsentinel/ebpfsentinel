//! The integer syntax Suricata keywords share: `N`, `=N`, `!N`, `!=N`, `<N`,
//! `<=N`, `>N`, `>=N`, the exclusive ranges `N-M` and `N<>M`, the negated
//! range `!N-M`, and the bitmask forms `&MASK=V` and `&MASK!=V`. Numbers are
//! decimal or `0x` hexadecimal; a size may carry a `kb`, `mb` or `gb` unit.

/// How an integer is compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    /// Strictly between the two bounds.
    Range,
    /// Outside the open interval: below or at the low bound, at or above the
    /// high one.
    NotRange,
    /// `value & mask == expected`.
    MaskEq,
    /// `value & mask != expected`.
    MaskNe,
}

/// One integer condition: `op` applied with `a` (and `b` for a range or a
/// bitmask, where `a` is the mask and `b` the expected value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntMatch {
    pub op: IntOp,
    pub a: u64,
    pub b: u64,
}

impl IntMatch {
    #[must_use]
    pub const fn eq(value: u64) -> Self {
        Self {
            op: IntOp::Eq,
            a: value,
            b: 0,
        }
    }

    /// Whether `value` satisfies the condition.
    #[must_use]
    pub fn matches(&self, value: u64) -> bool {
        match self.op {
            IntOp::Eq => value == self.a,
            IntOp::Ne => value != self.a,
            IntOp::Lt => value < self.a,
            IntOp::Le => value <= self.a,
            IntOp::Gt => value > self.a,
            IntOp::Ge => value >= self.a,
            IntOp::Range => value > self.a && value < self.b,
            IntOp::NotRange => value <= self.a || value >= self.b,
            IntOp::MaskEq => value & self.a == self.b,
            IntOp::MaskNe => value & self.a != self.b,
        }
    }

    /// Parse the integer syntax, refusing anything above `max`.
    ///
    /// # Errors
    ///
    /// A message naming what is wrong with the text.
    pub fn parse(text: &str, max: u64) -> Result<Self, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("is empty where a number goes".to_string());
        }
        let checked = |m: Self| -> Result<Self, String> {
            if m.a > max || (m.b > max && !matches!(m.op, IntOp::MaskEq | IntOp::MaskNe)) {
                return Err(format!("'{text}' is above {max}"));
            }
            Ok(m)
        };
        if let Some(rest) = text.strip_prefix('&') {
            let (mask, op, expected) = if let Some((mask, expected)) = rest.split_once("!=") {
                (mask, IntOp::MaskNe, expected)
            } else if let Some((mask, expected)) = rest.split_once('=') {
                (mask, IntOp::MaskEq, expected)
            } else {
                return Err(format!("'{text}' is a bitmask without '=' or '!='"));
            };
            return checked(Self {
                op,
                a: number(mask)?,
                b: number(expected)?,
            });
        }
        if let Some(rest) = text.strip_prefix("!=") {
            return checked(Self {
                op: IntOp::Ne,
                a: number(rest)?,
                b: 0,
            });
        }
        if let Some(rest) = text.strip_prefix('!') {
            if let Some((low, high)) = split_range(rest) {
                return checked(range(IntOp::NotRange, low, high, text)?);
            }
            return checked(Self {
                op: IntOp::Ne,
                a: number(rest)?,
                b: 0,
            });
        }
        for (prefix, op) in [
            (">=", IntOp::Ge),
            ("<=", IntOp::Le),
            (">", IntOp::Gt),
            ("<", IntOp::Lt),
            ("=", IntOp::Eq),
        ] {
            if let Some(rest) = text.strip_prefix(prefix) {
                return checked(Self {
                    op,
                    a: number(rest)?,
                    b: 0,
                });
            }
        }
        if let Some((low, high)) = split_range(text) {
            return checked(range(IntOp::Range, low, high, text)?);
        }
        checked(Self::eq(number(text)?))
    }
}

fn split_range(text: &str) -> Option<(&str, &str)> {
    if let Some(split) = text.split_once("<>") {
        return Some(split);
    }
    // A leading minus is not a range; the first '-' after a digit is.
    let index = text
        .char_indices()
        .skip(1)
        .find(|(_, ch)| *ch == '-')
        .map(|(index, _)| index)?;
    Some((&text[..index], &text[index + 1..]))
}

fn range(op: IntOp, low: &str, high: &str, text: &str) -> Result<IntMatch, String> {
    let (a, b) = (number(low)?, number(high)?);
    if a >= b {
        return Err(format!(
            "'{text}' is a range whose low bound is not below its high one"
        ));
    }
    Ok(IntMatch { op, a, b })
}

/// One unsigned number, decimal or `0x` hexadecimal, with an optional size
/// unit.
///
/// # Errors
///
/// A message naming the text that is not a number.
pub fn number(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let lower = text.to_ascii_lowercase();
    let (digits, scale) = [("kb", 1u64 << 10), ("mb", 1 << 20), ("gb", 1 << 30)]
        .iter()
        .find_map(|(unit, scale)| lower.strip_suffix(unit).map(|d| (d.trim(), *scale)))
        .unwrap_or((lower.as_str(), 1));
    let value = if let Some(hex) = digits.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        digits.parse::<u64>()
    }
    .map_err(|_| format!("'{text}' is not a number"))?;
    value
        .checked_mul(scale)
        .ok_or_else(|| format!("'{text}' does not fit in 64 bits"))
}

/// One signed number, decimal or `0x` hexadecimal.
///
/// # Errors
///
/// A message naming the text that is not a number.
pub fn signed(text: &str) -> Result<i64, String> {
    let text = text.trim();
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let magnitude = number(digits)?;
    let magnitude = i64::try_from(magnitude).map_err(|_| format!("'{text}' is out of range"))?;
    Ok(if negative { -magnitude } else { magnitude })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(text: &str) -> IntMatch {
        IntMatch::parse(text, u64::MAX).unwrap()
    }

    #[test]
    fn documented_forms_parse_and_evaluate() {
        assert!(p("5").matches(5) && !p("5").matches(6));
        assert!(p("=5").matches(5));
        assert!(p("!5").matches(4) && !p("!5").matches(5));
        assert!(p("!=5").matches(4));
        assert!(p("<5").matches(4) && !p("<5").matches(5));
        assert!(p("<=5").matches(5));
        assert!(p(">5").matches(6) && !p(">5").matches(5));
        assert!(p(">=5").matches(5));
        assert!(p("< 5").matches(4));
    }

    #[test]
    fn ranges_are_exclusive_in_both_spellings() {
        for text in ["5-10", "5<>10"] {
            let m = p(text);
            assert!(!m.matches(5) && m.matches(6) && m.matches(9) && !m.matches(10));
        }
        let m = p("!5-10");
        assert!(m.matches(5) && !m.matches(7) && m.matches(10));
        assert!(IntMatch::parse("10-5", u64::MAX).is_err());
        assert!(IntMatch::parse("5-5", u64::MAX).is_err());
    }

    #[test]
    fn bitmasks_compare_the_masked_value() {
        let m = p("&0xf0=0x10");
        assert!(m.matches(0x1f) && !m.matches(0x2f));
        let m = p("&0xf0!=0x10");
        assert!(!m.matches(0x1f) && m.matches(0x2f));
    }

    #[test]
    fn numbers_take_hex_and_units() {
        assert_eq!(number("0x10").unwrap(), 16);
        assert_eq!(number("2kb").unwrap(), 2048);
        assert_eq!(number("1MB").unwrap(), 1 << 20);
        assert!(number("ten").is_err());
        assert_eq!(signed("-12").unwrap(), -12);
    }

    #[test]
    fn values_above_the_field_are_refused() {
        assert!(IntMatch::parse("256", 255).is_err());
        assert!(IntMatch::parse("<255", 255).is_ok());
    }
}

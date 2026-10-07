//! Plain-text tables for the CLI.
//!
//! Every column is as wide as its widest cell, header included, so a value
//! longer than the usual one widens its column instead of pushing every cell
//! after it out from under its header. A column aligned right is aligned
//! right in the header too, so a number sits under the end of its label.

use std::fmt::Write as _;

/// Which side of its column a cell sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    Left,
    Right,
}

/// Space between two columns.
const GAP: &str = "  ";

/// A table buffered until every row is known, then printed with each column
/// sized to its content.
#[derive(Debug)]
pub struct Table {
    headers: Vec<&'static str>,
    align: Vec<Align>,
    rows: Vec<Vec<String>>,
    indent: &'static str,
}

impl Table {
    /// A table with these columns, left to right.
    pub fn new(columns: &[(&'static str, Align)]) -> Self {
        Self {
            headers: columns.iter().map(|(h, _)| *h).collect(),
            align: columns.iter().map(|(_, a)| *a).collect(),
            rows: Vec::new(),
            indent: "",
        }
    }

    /// Prefix every line, for a table nested under a heading.
    pub fn indent(mut self, indent: &'static str) -> Self {
        self.indent = indent;
        self
    }

    /// Append one row. A row shorter than the header leaves its last cells
    /// empty; a longer one is cut to the header.
    pub fn row(&mut self, mut cells: Vec<String>) {
        cells.resize(self.headers.len(), String::new());
        self.rows.push(cells);
    }

    /// The table as text, one line per row, header first, each line ending
    /// with a newline and none carrying trailing spaces.
    pub fn render(&self) -> String {
        let mut widths: Vec<usize> = self.headers.iter().map(|h| width(h)).collect();
        for row in &self.rows {
            for (w, cell) in widths.iter_mut().zip(row) {
                *w = (*w).max(width(cell));
            }
        }
        let mut out = String::new();
        self.line(&mut out, &widths, self.headers.iter().copied());
        for row in &self.rows {
            self.line(&mut out, &widths, row.iter().map(String::as_str));
        }
        out
    }

    /// Print the table to stdout.
    pub fn print(&self) {
        print!("{}", self.render());
    }

    fn line<'a>(&self, out: &mut String, widths: &[usize], cells: impl Iterator<Item = &'a str>) {
        let mut line = String::from(self.indent);
        for (i, (cell, (&w, &align))) in cells.zip(widths.iter().zip(&self.align)).enumerate() {
            if i > 0 {
                line.push_str(GAP);
            }
            let pad = w - width(cell);
            match align {
                Align::Left => {
                    line.push_str(cell);
                    line.extend(std::iter::repeat_n(' ', pad));
                }
                Align::Right => {
                    line.extend(std::iter::repeat_n(' ', pad));
                    line.push_str(cell);
                }
            }
        }
        let _ = writeln!(out, "{}", line.trim_end());
    }
}

/// Columns a cell occupies on a terminal. Every cell the CLI prints is ASCII
/// or Latin text, where a character is one column.
fn width(s: &str) -> usize {
    s.chars().count()
}

/// Build a row from any mix of displayable values.
macro_rules! cells {
    ($($cell:expr),* $(,)?) => {
        vec![$(::std::string::ToString::to_string(&$cell)),*]
    };
}
pub(crate) use cells;

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(t: &Table) -> Vec<String> {
        t.render().lines().map(str::to_string).collect()
    }

    /// The defect this module exists for: a long first cell used to push
    /// every later cell out from under its header.
    #[test]
    fn a_long_cell_widens_its_column_and_keeps_the_next_one_aligned() {
        let mut t = Table::new(&[("ID", Align::Left), ("SEVERITY", Align::Left)]);
        t.row(cells!["1791209384279543016-ddos-1-0", "critical"]);
        t.row(cells!["short", "low"]);
        let l = lines(&t);
        let col = l[0].find("SEVERITY").unwrap();
        assert_eq!(l[1].find("critical"), Some(col));
        assert_eq!(l[2].find("low"), Some(col));
    }

    #[test]
    fn a_right_aligned_column_ends_under_the_end_of_its_header() {
        let mut t = Table::new(&[("NAME", Align::Left), ("PEAK PPS", Align::Right)]);
        t.row(cells!["ddos-1", 3496]);
        t.row(cells!["ddos-2", 7]);
        let l = lines(&t);
        let end = l[0].len();
        assert!(l[1].ends_with("3496") && l[1].len() == end);
        assert!(l[2].ends_with('7') && l[2].len() == end);
    }

    #[test]
    fn no_line_carries_trailing_spaces() {
        let mut t = Table::new(&[("A", Align::Left), ("LONG HEADER", Align::Left)]);
        t.row(cells!["x", "y"]);
        assert!(t.render().lines().all(|l| l == l.trim_end()));
    }

    #[test]
    fn an_indent_prefixes_every_line() {
        let mut t = Table::new(&[("A", Align::Left)]).indent("  ");
        t.row(cells!["x"]);
        assert_eq!(t.render(), "  A\n  x\n");
    }

    #[test]
    fn width_counts_characters_not_bytes() {
        let mut t = Table::new(&[("CITY", Align::Left), ("N", Align::Right)]);
        t.row(cells!["Zürich", 1]);
        t.row(cells!["Bern", 22]);
        let l = lines(&t);
        assert_eq!(l[1].chars().count(), l[2].chars().count());
    }
}

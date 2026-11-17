//! Every operation an agent serves is reached by a command, or excluded with
//! a reason.
//!
//! Three inputs: the agent's `OpenAPI` document, the sources of the client the
//! command line calls it through, and an exclusion file. A client names each
//! route right after the verb, as a literal (`Method::GET, "/api/v1/..."`) or
//! as the template of a `format!` whose placeholders are the path
//! parameters, so the routes it calls are read off its source without
//! compiling it; a request that builds its path somewhere else is refused,
//! because nothing could see what it reaches.
//!
//! The check fails on an operation no command reaches and no exclusion names,
//! on a route the client calls that the document does not describe, on an
//! exclusion whose route is gone or is now reached anyway, and on an
//! exclusion that does not say why. An agent that serves another edition's
//! command line may leave one of its routes unserved on purpose: the file
//! says so in an `[[unserved]]` table, with its reason, and the command then
//! refuses in words rather than meeting a 404. The OSS agent and the enterprise agent run
//! the same check against their own documents.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// One method on one path, the path's parameters written `{}` whatever the
/// two sides call them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Operation {
    pub method: String,
    pub path: String,
}

impl Operation {
    #[must_use]
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.to_ascii_uppercase(),
            path: normalise(path),
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.method, self.path)
    }
}

/// What can stop the check from reading its inputs.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the OpenAPI document does not parse: {0}")]
    Document(#[from] serde_json::Error),
    #[error("the OpenAPI document carries no paths object")]
    NoPaths,
    #[error("the exclusion file, line {line}: {why}")]
    Exclusions { line: usize, why: String },
}

/// The shortest reason an exclusion may give, so "n/a" is not one.
pub const MIN_REASON_CHARS: usize = 30;

/// Which way an entry of the file departs from the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The document describes it, and no command reaches it.
    Exclude,
    /// A command calls it, and this agent does not serve it.
    Unserved,
}

/// An operation the command line does not reach on purpose, or calls where
/// this agent serves nothing, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exclusion {
    pub kind: Kind,
    pub method: String,
    pub path: String,
    pub reason: String,
}

impl Exclusion {
    fn operation(&self) -> Operation {
        Operation::new(&self.method, &self.path)
    }
}

/// The exclusion file: `[[exclude]]` and `[[unserved]]` tables, each holding `method`, `path`
/// and `reason` as basic strings on one line, with `#` comments and blank
/// lines between. That is all of TOML the file uses, so that is all this
/// reads; anything else is refused with its line rather than guessed at.
///
/// # Errors
///
/// The first line that is not that, or a table missing a key.
pub fn exclusions(text: &str) -> Result<Vec<Exclusion>, Error> {
    fn finish(
        table: Option<(usize, Kind, BTreeMap<String, String>)>,
        out: &mut Vec<Exclusion>,
    ) -> Result<(), Error> {
        let Some((line, kind, mut keys)) = table else {
            return Ok(());
        };
        let mut take = |key: &str| {
            keys.remove(key).ok_or_else(|| Error::Exclusions {
                line,
                why: format!("the table names no {key}"),
            })
        };
        out.push(Exclusion {
            kind,
            method: take("method")?,
            path: take("path")?,
            reason: take("reason")?,
        });
        Ok(())
    }
    let mut out = Vec::new();
    let mut table: Option<(usize, Kind, BTreeMap<String, String>)> = None;
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let fail = |why: &str| Error::Exclusions {
            line,
            why: why.to_string(),
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let header = match trimmed {
            "[[exclude]]" => Some(Kind::Exclude),
            "[[unserved]]" => Some(Kind::Unserved),
            _ => None,
        };
        if let Some(kind) = header {
            finish(table.take(), &mut out)?;
            table = Some((line, kind, BTreeMap::new()));
            continue;
        }
        let Some((_, _, keys)) = table.as_mut() else {
            return Err(fail("a key outside an [[exclude]] or [[unserved]] table"));
        };
        let (key, value) = trimmed
            .split_once('=')
            .ok_or_else(|| fail("neither a table header nor key = \"value\""))?;
        let key = key.trim();
        if !matches!(key, "method" | "path" | "reason") {
            return Err(fail(&format!("{key} is not method, path or reason")));
        }
        let value =
            basic_string(value.trim()).ok_or_else(|| fail("the value is not one quoted string"))?;
        if keys.insert(key.to_string(), value).is_some() {
            return Err(fail(&format!("{key} is given twice")));
        }
    }
    finish(table, &mut out)?;
    Ok(out)
}

/// A TOML basic string on one line, with its escapes, and an optional comment
/// after it.
fn basic_string(text: &str) -> Option<String> {
    let mut chars = text.strip_prefix('"')?.chars();
    let mut out = String::new();
    loop {
        match chars.next()? {
            '"' => break,
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                't' => out.push('\t'),
                _ => return None,
            },
            c => out.push(c),
        }
    }
    let rest = chars.as_str().trim();
    (rest.is_empty() || rest.starts_with('#')).then_some(out)
}

/// Every operation the document describes.
///
/// # Errors
///
/// When the text is not an `OpenAPI` document with paths.
pub fn documented(openapi: &str) -> Result<BTreeSet<Operation>, Error> {
    let spec: serde_json::Value = serde_json::from_str(openapi)?;
    let paths = spec["paths"].as_object().ok_or(Error::NoPaths)?;
    let mut operations = BTreeSet::new();
    for (path, item) in paths {
        let Some(item) = item.as_object() else {
            continue;
        };
        for method in item.keys() {
            let upper = method.to_ascii_uppercase();
            if matches!(
                upper.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
            ) {
                operations.insert(Operation::new(&upper, path));
            }
        }
    }
    Ok(operations)
}

/// A request whose route could not be read off the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anonymous {
    pub file: String,
    pub method: String,
}

/// The routes the client sources call, and the requests whose route is not
/// written beside the verb. Only the shipped half of each file is read: what
/// follows its first `#[cfg(test)]` names routes no command calls.
#[must_use]
pub fn requested(sources: &[(String, String)]) -> (BTreeSet<Operation>, Vec<Anonymous>) {
    const MARKER: &str = "Method::";
    let mut operations = BTreeSet::new();
    let mut anonymous = Vec::new();
    for (file, text) in sources {
        let src = text
            .find("#[cfg(test)]")
            .map_or(text.as_str(), |at| &text[..at]);
        let mut from = 0usize;
        while let Some(rel) = src[from..].find(MARKER) {
            let at = from + rel;
            let after = at + MARKER.len();
            from = after;
            // `http::Method::` and `reqwest::Method::` both count; an
            // identifier merely ending in `Method` does not.
            if src[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                continue;
            }
            let verb: String = src[after..]
                .chars()
                .take_while(char::is_ascii_uppercase)
                .collect();
            if verb.is_empty() {
                continue;
            }
            // The route is the argument right after the verb: a literal, or
            // the template of a `format!` whose placeholders are the path
            // parameters. A path held in a variable or assembled elsewhere is
            // not a route anyone can read here.
            let rest = src[after + verb.len()..].trim_start();
            let literal = rest
                .strip_prefix(',')
                .map(str::trim_start)
                .map(|arg| arg.strip_prefix('&').unwrap_or(arg))
                .map(|arg| arg.strip_prefix("format!(").unwrap_or(arg))
                .and_then(|arg| arg.strip_prefix('"'))
                .and_then(|arg| arg.find('"').map(|close| &arg[..close]));
            match literal {
                Some(path) => {
                    operations.insert(Operation::new(&verb, path));
                }
                None => anonymous.push(Anonymous {
                    file: file.clone(),
                    method: verb,
                }),
            }
        }
    }
    (operations, anonymous)
}

/// Every `.rs` file under `path`, or `path` itself when it is a file, with
/// its text, sorted so the report reads the same on every machine.
///
/// # Errors
///
/// A directory that does not list or a file that does not read.
pub fn sources(path: &std::path::Path, out: &mut Vec<(String, String)>) -> std::io::Result<()> {
    if path.is_file() {
        out.push((path.display().to_string(), std::fs::read_to_string(path)?));
        return Ok(());
    }
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(path)?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    entries.sort();
    for entry in entries {
        if entry.is_dir() || entry.extension().is_some_and(|ext| ext == "rs") {
            sources(&entry, out)?;
        }
    }
    Ok(())
}

/// What the check found.
#[derive(Debug, Default)]
pub struct Report {
    /// Operations described in the document.
    pub documented: usize,
    /// Of those, reached by a command.
    pub reached: usize,
    /// Of those, excluded with a reason.
    pub excluded: usize,
    /// Called by the client, left unserved here with a reason.
    pub unserved: usize,
    /// Described, not reached, not excluded.
    pub unreached: Vec<Operation>,
    /// Called by the client, described nowhere.
    pub undocumented: Vec<Operation>,
    /// Requests whose route is not written beside the verb.
    pub anonymous: Vec<Anonymous>,
    /// Exclusions that no longer hold, each with what is wrong with it.
    pub stale: Vec<(Exclusion, &'static str)>,
}

impl Report {
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.unreached.is_empty()
            && self.undocumented.is_empty()
            && self.anonymous.is_empty()
            && self.stale.is_empty()
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} operations: {} reached by a command, {} excluded with a reason",
            self.documented, self.reached, self.excluded
        )?;
        if self.unserved > 0 {
            writeln!(
                f,
                "{} calls the client makes are not served here, each with a reason",
                self.unserved
            )?;
        }
        for op in &self.unreached {
            writeln!(f, "  unreached: {op} has no command and no exclusion")?;
        }
        for op in &self.undocumented {
            writeln!(
                f,
                "  undocumented: the client calls {op}, which the document does not describe"
            )?;
        }
        for a in &self.anonymous {
            writeln!(
                f,
                "  anonymous: a {} request in {} builds its path away from the verb; pass the route as a literal and the parameters on the query",
                a.method, a.file
            )?;
        }
        for (e, why) in &self.stale {
            writeln!(f, "  stale exclusion: {} {}: {why}", e.method, e.path)?;
        }
        Ok(())
    }
}

/// Hold the client to the document, through the exclusions.
#[must_use]
pub fn check(
    documented: &BTreeSet<Operation>,
    requested: &BTreeSet<Operation>,
    anonymous: Vec<Anonymous>,
    exclusions: &[Exclusion],
) -> Report {
    let mut seen: BTreeMap<Operation, usize> = BTreeMap::new();
    let mut stale = Vec::new();
    for e in exclusions {
        let op = e.operation();
        *seen.entry(op.clone()).or_default() += 1;
        let why = if seen[&op] > 1 {
            Some("listed twice")
        } else if e.kind == Kind::Unserved && documented.contains(&op) {
            Some("the document describes it now, so it is served")
        } else if e.kind == Kind::Unserved && !requested.contains(&op) {
            Some("no command calls it any more")
        } else if e.kind == Kind::Exclude && !documented.contains(&op) {
            Some("the document no longer describes it")
        } else if e.kind == Kind::Exclude && requested.contains(&op) {
            Some("a command reaches it now, so the exclusion goes")
        } else if e.reason.trim().chars().count() < MIN_REASON_CHARS {
            Some("the reason does not say why")
        } else {
            None
        };
        if let Some(why) = why {
            stale.push((e.clone(), why));
        }
    }
    let of = |kind: Kind| -> BTreeSet<Operation> {
        exclusions
            .iter()
            .filter(|e| e.kind == kind)
            .map(Exclusion::operation)
            .collect()
    };
    let excluded = of(Kind::Exclude);
    let unserved = of(Kind::Unserved);
    Report {
        documented: documented.len(),
        reached: documented.intersection(requested).count(),
        excluded: documented.intersection(&excluded).count(),
        unserved: requested
            .difference(documented)
            .filter(|op| unserved.contains(op))
            .count(),
        unreached: documented
            .iter()
            .filter(|op| !requested.contains(op) && !excluded.contains(op))
            .cloned()
            .collect(),
        undocumented: requested
            .difference(documented)
            .filter(|op| !unserved.contains(op))
            .cloned()
            .collect(),
        anonymous,
        stale,
    }
}

/// Collapse `{id}` and friends, and drop a query string, so a path with a
/// parameter compares equal however the two sides spell it.
#[must_use]
pub fn normalise(path: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    let mut out = String::with_capacity(path.len());
    let mut depth = 0usize;
    for ch in path.chars() {
        match ch {
            '{' => {
                depth += 1;
                if depth == 1 {
                    out.push_str("{}");
                }
            }
            '}' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"{"paths":{
        "/api/v1/rules":{"get":{},"post":{}},
        "/api/v1/rules/{id}":{"delete":{},"parameters":[]},
        "/api/v1/peer":{"post":{}}
    }}"#;

    fn src(text: &str) -> Vec<(String, String)> {
        vec![("client.rs".to_string(), text.to_string())]
    }

    fn reason() -> String {
        "only the peer agent calls it, over its own mutual TLS link".to_string()
    }

    #[test]
    fn a_parameter_compares_equal_however_it_is_spelt() {
        assert_eq!(normalise("/a/{rule_id}/b?x=1"), "/a/{}/b");
        assert_eq!(
            Operation::new("delete", "/x/{id}"),
            Operation::new("DELETE", "/x/{}")
        );
    }

    #[test]
    fn the_document_yields_methods_and_not_path_level_keys() {
        let ops = documented(DOC).unwrap();
        assert_eq!(ops.len(), 4);
        assert!(ops.contains(&Operation::new("DELETE", "/api/v1/rules/{}")));
    }

    #[test]
    fn routes_are_read_off_the_shipped_half_only() {
        let (ops, anonymous) = requested(&src(r#"
            self.request(reqwest::Method::GET, "/api/v1/rules")
            self.request(Method::DELETE, &format!("/api/v1/rules/{id}"))
            self.request(Method::PUT, &path)
            self.request(http::Method::POST, "/api/v1/rules")
            fn notMethod::GET() {}
            #[cfg(test)]
            self.request(reqwest::Method::POST, "/api/v1/peer")
            "#));
        assert_eq!(
            ops,
            BTreeSet::from([
                Operation::new("GET", "/api/v1/rules"),
                Operation::new("POST", "/api/v1/rules"),
                Operation::new("DELETE", "/api/v1/rules/{}"),
            ])
        );
        assert_eq!(
            anonymous,
            vec![Anonymous {
                file: "client.rs".to_string(),
                method: "PUT".to_string()
            }]
        );
    }

    #[test]
    fn an_operation_needs_a_command_or_an_exclusion() {
        let doc = documented(DOC).unwrap();
        let (req, anon) = requested(&src(
            r#"Method::GET, "/api/v1/rules") Method::POST, "/api/v1/rules") Method::DELETE, "/api/v1/rules/{}")"#,
        ));
        let report = check(&doc, &req, anon.clone(), &[]);
        assert_eq!(
            report.unreached,
            vec![Operation::new("POST", "/api/v1/peer")]
        );
        assert!(!report.is_clean());

        let excluded = [Exclusion {
            kind: Kind::Exclude,
            method: "post".to_string(),
            path: "/api/v1/peer".to_string(),
            reason: reason(),
        }];
        let report = check(&doc, &req, anon, &excluded);
        assert!(report.is_clean(), "{report}");
        assert_eq!((report.reached, report.excluded), (3, 1));
    }

    #[test]
    fn an_exclusion_that_no_longer_holds_fails() {
        let doc = documented(DOC).unwrap();
        let (req, _) = requested(&src(r#"Method::POST, "/api/v1/peer")"#));
        let ex = |method: &str, path: &str, reason: String| Exclusion {
            kind: Kind::Exclude,
            method: method.to_string(),
            path: path.to_string(),
            reason,
        };
        let report = check(
            &doc,
            &req,
            Vec::new(),
            &[
                ex("POST", "/api/v1/peer", reason()),
                ex("GET", "/api/v1/gone", reason()),
                ex("GET", "/api/v1/rules", "n/a".to_string()),
                ex("GET", "/api/v1/rules", reason()),
            ],
        );
        let whys: Vec<&str> = report.stale.iter().map(|(_, why)| *why).collect();
        assert_eq!(
            whys,
            vec![
                "a command reaches it now, so the exclusion goes",
                "the document no longer describes it",
                "the reason does not say why",
                "listed twice",
            ]
        );
    }

    #[test]
    fn a_route_the_document_does_not_describe_fails() {
        let doc = documented(DOC).unwrap();
        let (req, _) = requested(&src(r#"Method::GET, "/api/v1/nowhere")"#));
        let report = check(&doc, &req, Vec::new(), &[]);
        assert_eq!(
            report.undocumented,
            vec![Operation::new("GET", "/api/v1/nowhere")]
        );
    }

    #[test]
    fn a_call_left_unserved_here_needs_its_reason_and_its_caller() {
        let doc = documented(DOC).unwrap();
        let (req, _) = requested(&src(
            r#"Method::GET, "/api/v1/nowhere") Method::GET, "/api/v1/rules")"#,
        ));
        let entry = |method: &str, path: &str| Exclusion {
            kind: Kind::Unserved,
            method: method.to_string(),
            path: path.to_string(),
            reason: reason(),
        };
        let excluded = [
            Exclusion {
                kind: Kind::Exclude,
                ..entry("POST", "/api/v1/rules")
            },
            entry("DELETE", "/api/v1/rules/{id}"),
            entry("POST", "/api/v1/peer"),
        ];
        let mut all = excluded.to_vec();
        all.push(entry("GET", "/api/v1/nowhere"));
        let report = check(&doc, &req, Vec::new(), &all);
        assert!(report.undocumented.is_empty(), "{report}");
        assert_eq!(report.unserved, 1);
        let whys: Vec<&str> = report.stale.iter().map(|(_, why)| *why).collect();
        assert_eq!(
            whys,
            vec![
                "the document describes it now, so it is served",
                "the document describes it now, so it is served",
            ]
        );

        let report = check(&doc, &req, Vec::new(), &excluded);
        assert_eq!(
            report.undocumented,
            vec![Operation::new("GET", "/api/v1/nowhere")]
        );

        let (none, _) = requested(&src(""));
        let report = check(&BTreeSet::new(), &none, Vec::new(), &[entry("GET", "/x")]);
        assert_eq!(report.stale[0].1, "no command calls it any more");
    }

    #[test]
    fn the_exclusion_file_is_a_list_of_tables() {
        let parsed = exclusions(
            "[[exclude]]\nmethod = \"POST\"\npath = \"/api/v1/peer\"\nreason = \"why\"\n",
        )
        .unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, Kind::Exclude);
        let parsed =
            exclusions("[[unserved]]\nmethod = \"GET\"\npath = \"/x\"\nreason = \"r\"\n").unwrap();
        assert_eq!(parsed[0].kind, Kind::Unserved);
        assert!(exclusions("").unwrap().is_empty());
        assert!(exclusions("[[exclude]]\nmethod = \"POST\"\n").is_err());
        assert!(
            exclusions("[[exclude]]\nmethod=\"A\"\npath=\"/\"\nreason=\"r\"\nextra=1\n").is_err()
        );
    }
}

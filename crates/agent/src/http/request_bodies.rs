//! Every request body refuses a field it does not know.
//!
//! A misspelt key in a write is otherwise dropped on the floor and the rule
//! is created without it: a deny rule whose `dst_port` was typed `dstport`
//! matches every port. The test reads the handlers' sources, takes every type
//! a handler extracts as `Json<T>`, follows the types those name in this
//! directory, and requires `deny_unknown_fields` on each one.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The attribute lines and the body of each struct or enum declared in the
/// sources, by name.
fn declarations(sources: &[String]) -> BTreeMap<String, (String, String)> {
    let mut out = BTreeMap::new();
    for source in sources {
        let lines: Vec<&str> = source.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            let Some(rest) = [
                "pub struct ",
                "pub(crate) struct ",
                "pub enum ",
                "pub(crate) enum ",
            ]
            .iter()
            .find_map(|p| trimmed.strip_prefix(p)) else {
                continue;
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let mut attrs = String::new();
            let mut j = i;
            while j > 0 {
                let above = lines[j - 1].trim_start();
                if above.starts_with("#[") || above.starts_with("///") {
                    attrs.push_str(above);
                    attrs.push('\n');
                    j -= 1;
                } else {
                    break;
                }
            }
            let mut body = String::new();
            let mut depth = 0i32;
            let mut opened = false;
            for next in &lines[i..] {
                body.push_str(next);
                body.push('\n');
                depth += i32::try_from(next.matches('{').count()).unwrap_or(0);
                depth -= i32::try_from(next.matches('}').count()).unwrap_or(0);
                opened |= next.contains('{');
                if (opened && depth <= 0) || (!opened && next.contains(';')) {
                    break;
                }
            }
            out.insert(name, (attrs, body));
        }
    }
    out
}

/// Type names a handler extracts as its JSON body, required or optional.
fn extracted_bodies(sources: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for source in sources {
        let mut rest = source.as_str();
        while let Some(at) = rest.find("Json<") {
            let before = &rest[..at];
            let after = &rest[at + "Json<".len()..];
            if before.ends_with("): ") || before.ends_with(": Option<") {
                let name: String = after
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    out.insert(name);
                }
            }
            rest = after;
        }
    }
    out
}

fn identifiers(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|w| w.starts_with(|c: char| c.is_ascii_uppercase()))
}

/// Every body type and every type of this directory it reaches, with whether
/// it refuses unknown fields.
pub(crate) fn body_types(dir: &Path) -> BTreeMap<String, bool> {
    let mut sources = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).expect("handler directory is readable") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                sources.push(std::fs::read_to_string(&path).expect("source is readable"));
            }
        }
    }
    let decls = declarations(&sources);
    let mut seen = BTreeMap::new();
    let mut todo: Vec<String> = extracted_bodies(&sources).into_iter().collect();
    while let Some(name) = todo.pop() {
        let Some((attrs, body)) = decls.get(&name) else {
            continue;
        };
        if seen.contains_key(&name) {
            continue;
        }
        seen.insert(name.clone(), attrs.contains("deny_unknown_fields"));
        todo.extend(
            identifiers(body)
                .skip(1)
                .filter(|w| decls.contains_key(*w))
                .map(str::to_string),
        );
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_request_body_refuses_unknown_fields() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/http");
        let types = body_types(&dir);
        assert!(
            types.len() >= 25,
            "the scan found only {} body types: {types:?}",
            types.len()
        );
        let open: Vec<&String> = types
            .iter()
            .filter(|(_, denies)| !**denies)
            .map(|(name, _)| name)
            .collect();
        assert!(
            open.is_empty(),
            "request bodies accepting unknown fields: {open:?}"
        );
    }

    #[test]
    fn a_misspelt_key_in_a_rule_is_refused() {
        let body = r#"{"id":"fw-1","priority":10,"action":"deny","dstport":"22"}"#;
        let Err(err) =
            serde_json::from_str::<super::super::firewall_handler::CreateRuleRequest>(body)
        else {
            panic!("an unknown key is refused");
        };
        assert!(err.to_string().contains("dstport"), "{err}");
    }
}

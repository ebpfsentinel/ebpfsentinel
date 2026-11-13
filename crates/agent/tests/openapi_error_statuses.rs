//! Every error status a handler builds is a status its operation declares.
//!
//! A generated client only knows the answers the document lists, so a 404 for
//! a feature switched off, or a 503 for a store not yet open, that the
//! document never names reaches it as an undescribed failure. This reads each
//! `#[utoipa::path(...)]` handler under `src/http/`, collects the `ApiError`
//! variants built directly in its body, and fails on a status the annotation
//! leaves out. Helpers the body calls are not followed, so this undercounts and
//! never invents a status the handler cannot build.

use std::collections::BTreeSet;
use std::path::Path;

const STATUSES: &[(&str, &str)] = &[
    ("BadRequest", "400"),
    ("NotFound", "404"),
    ("Conflict", "409"),
    ("Internal", "500"),
    ("ServiceUnavailable", "503"),
];

/// Index of the delimiter closing the one opened at `open`.
fn closing(source: &str, open: usize, left: u8, right: u8) -> usize {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    for (offset, byte) in bytes[open..].iter().enumerate() {
        if *byte == left {
            depth += 1;
        } else if *byte == right {
            depth -= 1;
            if depth == 0 {
                return open + offset;
            }
        }
    }
    source.len()
}

fn declared(attr: &str) -> BTreeSet<String> {
    attr.match_indices("status = ")
        .filter_map(|(at, found)| attr.get(at + found.len()..at + found.len() + 3))
        .map(str::to_string)
        .collect()
}

fn built(body: &str) -> BTreeSet<String> {
    STATUSES
        .iter()
        .filter(|(variant, _)| body.contains(&format!("ApiError::{variant}")))
        .map(|(_, status)| (*status).to_string())
        .collect()
}

/// `(handler, missing statuses)` for every annotated handler in one file.
fn undeclared(source: &str) -> Vec<(String, Vec<String>)> {
    let mut found = Vec::new();
    for (start, marker) in source.match_indices("#[utoipa::path(") {
        let attr_end = closing(source, start + marker.len() - 1, b'(', b')');
        let attr = &source[start..attr_end];
        let Some(fn_at) = source[attr_end..]
            .find("pub async fn ")
            .map(|i| attr_end + i)
        else {
            continue;
        };
        let name: String = source[fn_at + "pub async fn ".len()..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let params_end = closing(
            source,
            source[fn_at..].find('(').map_or(fn_at, |i| fn_at + i),
            b'(',
            b')',
        );
        let Some(body_at) = source[params_end..].find('{').map(|i| params_end + i) else {
            continue;
        };
        let body = &source[body_at..closing(source, body_at, b'{', b'}')];
        let missing: Vec<String> = built(body).difference(&declared(attr)).cloned().collect();
        if !missing.is_empty() {
            found.push((name, missing));
        }
    }
    found
}

#[test]
fn the_scanner_sees_a_status_left_out() {
    let source = r#"
#[utoipa::path(get, path = "/x", responses((status = 200, description = "ok")))]
pub async fn handler(State(s): State<Arc<AppState>>) -> Result<Json<()>, ApiError> {
    let _ = ApiError::NotFound { code: "X", message: String::new() };
    Ok(Json(()))
}
"#;
    assert_eq!(
        undeclared(source),
        vec![("handler".to_string(), vec!["404".to_string()])]
    );
}

#[test]
fn every_error_status_a_handler_builds_is_declared() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/http");
    let mut handlers = 0usize;
    let mut missing = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("the handlers directory is readable") {
        let path = entry.expect("a directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("a handler file is readable");
        handlers += source.matches("#[utoipa::path(").count();
        for (name, statuses) in undeclared(&source) {
            missing.push(format!(
                "{}::{name} builds {statuses:?}",
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default()
            ));
        }
    }
    assert!(
        handlers > 100,
        "the scan found only {handlers} annotated handlers"
    );
    assert!(
        missing.is_empty(),
        "error statuses absent from the document: {missing:#?}"
    );
}

//! What the OTLP exporter is built out of.
//!
//! The exporter's own defaults carry the two signals this product does not
//! emit and select a blocking HTTP client, which inside an asynchronous
//! agent means an export parking a runtime thread. None of that shows up as
//! a compile error, so it is asserted here: the manifest is read the way a
//! reviewer would read it, and a feature list edited back to the defaults
//! fails here rather than in production.

/// The workspace manifest, which is where every dependency of every crate
/// in the tree is declared.
fn workspace_manifest() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    std::fs::read_to_string(path).expect("the workspace manifest is readable")
}

/// The one line declaring `name`, comments and blank lines skipped.
fn declaration(manifest: &str, name: &str) -> String {
    manifest
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(&format!("{name} = ")))
        .unwrap_or_else(|| panic!("the workspace declares no {name}"))
        .to_string()
}

#[test]
fn the_exporter_takes_none_of_its_own_defaults() {
    let manifest = workspace_manifest();
    for crate_name in ["opentelemetry", "opentelemetry_sdk", "opentelemetry-otlp"] {
        let line = declaration(&manifest, crate_name);
        assert!(
            line.contains("default-features = false"),
            "{crate_name} takes its own defaults, which carry trace and metrics: {line}"
        );
    }
}

#[test]
fn the_exporter_asks_for_no_signal_it_does_not_emit() {
    let line = declaration(&workspace_manifest(), "opentelemetry-otlp");
    for signal in ["\"trace\"", "\"metrics\""] {
        assert!(
            !line.contains(signal),
            "the exporter compiles a signal the product never emits: {line}"
        );
    }
    assert!(
        line.contains("\"logs\""),
        "the exporter emits log records, so the logs feature is not optional: {line}"
    );
}

#[test]
fn the_http_exporter_never_links_the_blocking_client() {
    let line = declaration(&workspace_manifest(), "opentelemetry-otlp");
    assert!(
        !line.contains("reqwest-blocking-client"),
        "a blocking HTTP client inside an asynchronous agent parks a runtime thread per export: {line}"
    );
    assert!(
        line.contains("\"reqwest-client\""),
        "the HTTP exporter needs the asynchronous client named explicitly: {line}"
    );
    let reqwest = declaration(&workspace_manifest(), "reqwest");
    assert!(
        !reqwest.contains("\"blocking\""),
        "feature unification would hand the exporter a blocking client anyway: {reqwest}"
    );
}

#[test]
fn https_does_not_depend_on_another_crates_feature_set() {
    let line = declaration(&workspace_manifest(), "opentelemetry-otlp");
    assert!(
        line.contains("\"tls-aws-lc\"") || line.contains("\"tls\""),
        "the exporter must declare its own TLS backend rather than inherit one: {line}"
    );
    assert!(
        line.contains("\"tls-roots\"") || line.contains("\"tls-webpki-roots\""),
        "the exporter must declare where its trust anchors come from: {line}"
    );
}

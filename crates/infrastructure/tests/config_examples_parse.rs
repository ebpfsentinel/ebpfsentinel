// Regression guard: every shipped config under `config/` must parse and
// validate through the real loader, so docs, examples and the host profiles
// the packages install can never drift into a state that fails
// `ebpfsentinel-agent --config`.
use infrastructure::config::AgentConfig;

fn yaml_files_in(dir: &str) -> Vec<std::path::PathBuf> {
    let mut ents: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{dir}: {e}"))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    ents.sort();
    ents
}

#[test]
fn parse_all_examples() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config");
    let mut files: Vec<std::path::PathBuf> = vec![std::path::PathBuf::from(format!(
        "{root}/ebpfsentinel.yaml"
    ))];
    files.extend(yaml_files_in(&format!("{root}/examples")));

    // The three host profiles are shipped in the packages and in the tarball
    // and are meant to be copied over the configuration as they are, so a
    // profile that does not load is worse than an example that does not.
    let profiles = yaml_files_in(&format!("{root}/profiles"));
    assert!(
        profiles.len() >= 3,
        "the host profiles are missing from {root}/profiles"
    );
    files.extend(profiles);

    let mut fails = Vec::new();
    for f in &files {
        let yaml = std::fs::read_to_string(f).unwrap();
        match AgentConfig::from_yaml(&yaml) {
            Ok(_) => println!("OK   {}", f.file_name().unwrap().to_string_lossy()),
            Err(e) => {
                let name = f.file_name().unwrap().to_string_lossy().to_string();
                println!("FAIL {name}: {e}");
                fails.push(name);
            }
        }
    }
    assert!(fails.is_empty(), "examples failed to parse: {fails:?}");
}

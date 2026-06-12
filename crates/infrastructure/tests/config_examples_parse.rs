// Regression guard: every shipped example config under `config/` must parse and
// validate through the real loader, so docs and examples can never drift into a
// state that fails `ebpfsentinel-agent --config`.
use infrastructure::config::AgentConfig;

#[test]
fn parse_all_examples() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config");
    let mut files: Vec<std::path::PathBuf> = vec![std::path::PathBuf::from(format!(
        "{root}/ebpfsentinel.yaml"
    ))];
    let ex = format!("{root}/examples");
    let mut ents: Vec<_> = std::fs::read_dir(&ex)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    ents.sort();
    files.extend(ents);

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

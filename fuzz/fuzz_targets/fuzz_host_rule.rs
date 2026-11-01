#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;

use domain::firewall::workload::WorkloadFacts;
use domain::hostrule::{FieldType, FieldValue, HostRule, HostRuleSet, HostRuleSpec, IntentEvent};

// A host rule file is operator input that reaches the domain. The input is
// the rule list as the API and the configuration carry it: whatever
// deserialises either loads or is refused with a message, and whatever loads
// is evaluated against an event of each intention it names, every field
// filled from the input itself, so a matcher that panics on a value it
// accepted at load is a crash here rather than a dead agent.
fuzz_target!(|data: &[u8]| {
    let Ok(specs) = serde_json::from_slice::<Vec<HostRuleSpec>>(data) else {
        return;
    };
    let text = String::from_utf8_lossy(data);
    let number = i64::from(data.first().copied().unwrap_or(0));
    let mut loaded: Vec<HostRule> = Vec::new();
    for spec in specs.iter().cloned() {
        match HostRule::compile(spec) {
            Ok(rule) => loaded.push(rule),
            Err(error) => assert!(!error.to_string().is_empty()),
        }
    }
    // The set refuses what one rule refused, and an identifier used twice.
    let _ = HostRuleSet::compile(specs);
    let facts = WorkloadFacts {
        exe: Some(&text),
        unit: Some(&text),
        container_id: Some(&text),
        ..WorkloadFacts::default()
    };
    for rule in &loaded {
        for intent in rule.intents() {
            let mut event = IntentEvent::new(intent);
            for field in intent.fields() {
                let value = match field.ty {
                    FieldType::Text | FieldType::Path => FieldValue::Text(text.to_string()),
                    FieldType::Hash => FieldValue::Text("0".repeat(64)),
                    FieldType::Integer => FieldValue::Integer(number),
                    FieldType::Port => FieldValue::Integer(number),
                    FieldType::Address => FieldValue::Address(IpAddr::V4(Ipv4Addr::new(
                        10,
                        0,
                        0,
                        data.len().to_le_bytes()[0],
                    ))),
                    FieldType::Boolean => FieldValue::Boolean(number % 2 == 0),
                };
                event = match event.with(field.name, value) {
                    Ok(event) => event,
                    Err(error) => panic!("a registry field refused its own type: {error}"),
                };
            }
            let _ = rule.matches(&event, None);
            let _ = rule.matches(&event, Some(&facts));
        }
    }
});

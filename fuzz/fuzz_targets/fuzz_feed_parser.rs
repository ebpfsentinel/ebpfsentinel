#![no_main]

use libfuzzer_sys::fuzz_target;

use application::feed_update::parse_feed_data;
use domain::threatintel::entity::{FeedConfig, FeedFormat, FieldMapping};

/// Every format a feed body can arrive in, including STIX, which the target
/// used to leave out because its hand-copied parser had no equivalent.
const FORMATS: [FeedFormat; 4] = [
    FeedFormat::Plaintext,
    FeedFormat::Csv,
    FeedFormat::Json,
    FeedFormat::Stix,
];

/// Build a `FeedConfig` for the given format, with the ceilings the control
/// byte asked for.
fn feed_config(format: FeedFormat, control: u8) -> FeedConfig {
    FeedConfig {
        id: "fuzz".to_string(),
        name: "fuzz-feed".to_string(),
        url: "http://localhost/fuzz".to_string(),
        format,
        enabled: true,
        refresh_interval_secs: 3600,
        // Both ceilings are cut from the same byte so a body can be parsed
        // against a limit it actually reaches: pinning them high meant the
        // truncation and the confidence filter were never entered.
        max_iocs: usize::from(control),
        default_action: None,
        min_confidence: control,
        field_mapping: Some(FieldMapping {
            ip_field: "ip".to_string(),
            confidence_field: Some("confidence".to_string()),
            category_field: Some("category".to_string()),
            separator: ',',
            comment_prefix: Some("#".to_string()),
            skip_header: true,
        }),
        auth_header: None,
    }
}

fuzz_target!(|data: &[u8]| {
    let (control, body) = data
        .split_first()
        .map_or((0u8, &[][..]), |(first, rest)| (*first, rest));

    for format in FORMATS {
        let config = feed_config(format, control);

        // The parse the agent actually runs, rather than a copy of it living
        // in this file: a feed body reaching the engine goes through this one
        // call whether it came off HTTP or out of an offline bundle.
        let _ = parse_feed_data(&config, body);
    }
});

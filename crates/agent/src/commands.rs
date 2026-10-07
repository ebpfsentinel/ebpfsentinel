use anyhow::{Context, Result};

use crate::api_client::{
    AlertResponse, ApiClient, ConnectionResponse, ConntrackEventFrame, IdsRuleResponse,
    IpsRuleResponse, StreamOpenError,
};
use crate::cli::OutputFormat;
use crate::table::{Align, Table, cells};

// ── Health ──────────────────────────────────────────────────────────────

pub async fn cmd_health(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let (health, ready) = tokio::join!(client.healthz(), client.readyz());
    let health = health?;
    let ready = ready?;

    if output == OutputFormat::Json {
        let combined = serde_json::json!({
            "health": health,
            "ready": ready,
        });
        println!("{}", serde_json::to_string_pretty(&combined)?);
        return Ok(());
    }

    let ebpf = if ready.ebpf_loaded { "yes" } else { "no" };
    println!("Health:      {}", health.status);
    println!("Ready:       {}", ready.status);
    println!("eBPF loaded: {ebpf}");
    Ok(())
}

// ── Metrics ─────────────────────────────────────────────────────────────

pub async fn cmd_metrics(client: &ApiClient) -> Result<()> {
    let text = client.metrics().await?;
    print!("{text}");
    Ok(())
}

// ── Firewall ────────────────────────────────────────────────────────────

pub async fn cmd_firewall_list(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let rules = client.list_rules().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&rules)?);
        return Ok(());
    }

    if rules.is_empty() {
        println!("No firewall rules configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("PRI", Align::Right),
        ("ACTION", Align::Left),
        ("PROTO", Align::Left),
        ("SRC IP", Align::Left),
        ("DST IP", Align::Left),
        ("SRC PORT", Align::Right),
        ("DST PORT", Align::Right),
        ("SCOPE", Align::Left),
        ("INTERFACES", Align::Left),
        ("ENABLED", Align::Left),
    ]);

    for rule in &rules {
        table.row(cells![
            rule.id,
            rule.priority,
            rule.action,
            rule.protocol,
            rule.src_ip.as_deref().unwrap_or("-"),
            rule.dst_ip.as_deref().unwrap_or("-"),
            rule.src_port.as_deref().unwrap_or("-"),
            rule.dst_port.as_deref().unwrap_or("-"),
            rule.scope,
            interface_scope(&rule.interfaces),
            yes_no(rule.enabled)
        ]);
    }
    table.print();

    println!("\n{} rule(s) total.", rules.len());
    Ok(())
}

pub async fn cmd_firewall_add(client: &ApiClient, json: &str, output: OutputFormat) -> Result<()> {
    let body: serde_json::Value =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;
    let rule = client.create_rule(&body).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&rule)?);
        return Ok(());
    }

    println!(
        "Rule created: {} (priority={}, action={}, protocol={})",
        rule.id, rule.priority, rule.action, rule.protocol
    );
    Ok(())
}

pub async fn cmd_firewall_delete(client: &ApiClient, id: &str) -> Result<()> {
    client.delete_rule(id).await?;
    println!("Rule deleted: {id}");
    Ok(())
}

// ── L7 ──────────────────────────────────────────────────────────────────

pub async fn cmd_l7_list(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let rules = client.list_l7_rules().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&rules)?);
        return Ok(());
    }

    if rules.is_empty() {
        println!("No L7 rules configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("PRI", Align::Right),
        ("ACTION", Align::Left),
        ("SRC IP", Align::Left),
        ("DST IP", Align::Left),
        ("DST PORT", Align::Right),
        ("ENABLED", Align::Left),
    ]);

    for rule in &rules {
        table.row(cells![
            rule.id,
            rule.priority,
            rule.action,
            rule.src_ip.as_deref().unwrap_or("-"),
            rule.dst_ip.as_deref().unwrap_or("-"),
            rule.dst_port.as_deref().unwrap_or("-"),
            yes_no(rule.enabled)
        ]);
    }
    table.print();

    println!("\n{} rule(s) total.", rules.len());
    Ok(())
}

pub async fn cmd_l7_add(client: &ApiClient, json: &str, output: OutputFormat) -> Result<()> {
    let body: serde_json::Value =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;
    let rule = client.create_l7_rule(&body).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&rule)?);
        return Ok(());
    }

    println!(
        "L7 rule created: {} (priority={}, action={})",
        rule.id, rule.priority, rule.action
    );
    Ok(())
}

pub async fn cmd_l7_delete(client: &ApiClient, id: &str) -> Result<()> {
    client.delete_l7_rule(id).await?;
    println!("L7 rule deleted: {id}");
    Ok(())
}

// ── IPS ─────────────────────────────────────────────────────────────────

pub async fn cmd_ips_list(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let rules = client.list_ips_rules().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&rules)?);
        return Ok(());
    }

    if rules.is_empty() {
        println!("No IPS rules configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("SEVERITY", Align::Left),
        ("MODE", Align::Left),
        ("PROTO", Align::Left),
        ("MATCHES", Align::Left),
        ("PATTERN", Align::Left),
        ("INTERFACES", Align::Left),
        ("ENABLED", Align::Left),
    ]);

    for rule in &rules {
        table.row(cells![
            rule.id,
            rule.severity,
            rule.mode,
            rule.protocol,
            ips_rule_match(rule),
            rule.pattern,
            interface_scope(&rule.interfaces),
            yes_no(rule.enabled)
        ]);
    }
    table.print();

    println!("\n{} rule(s) total.", rules.len());

    // A rule that lost its kernel slot still prints as enabled above, which is
    // exactly the reading an operator must not walk away with.
    let shadowed: Vec<&IpsRuleResponse> =
        rules.iter().filter(|r| r.kernel_slot.is_some()).collect();
    if !shadowed.is_empty() {
        println!("\nKernel map slot conflicts:");
        for rule in shadowed {
            let Some(ref slot) = rule.kernel_slot else {
                continue;
            };
            let fate = if slot.evaluated_in_userspace {
                "still evaluated in userspace"
            } else {
                "ENFORCES NOTHING"
            };
            println!(
                "  {} loses its slot to {} - {}",
                rule.id,
                slot.shadowed_by.join(", "),
                fate,
            );
        }
    }
    Ok(())
}

/// What a prevention rule narrows on, the way the detection listing says it.
/// A rule decided on a resolved name carries no payload pattern, so a table
/// printing the port alone reads as a rule watching every packet on it.
fn ips_rule_match(rule: &IpsRuleResponse) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(port) = rule.dst_port {
        parts.push(format!("dst {port}"));
    }
    if let Some(ref domain) = rule.domain_pattern {
        let mode = rule.domain_match_mode.as_deref().unwrap_or("exact");
        parts.push(format!("{domain} ({mode})"));
    }
    if parts.is_empty() {
        return "-".to_string();
    }
    parts.join(" ")
}

pub async fn cmd_ips_blacklist(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let entries = client.list_ips_blacklist().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    if entries.is_empty() {
        println!("IPS blacklist is empty.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("IP", Align::Left),
        ("REASON", Align::Left),
        ("AUTO", Align::Left),
        ("TTL (s)", Align::Right),
    ]);

    for entry in &entries {
        table.row(cells![
            entry.ip,
            entry.reason,
            yes_no(entry.auto_generated),
            entry.ttl_remaining_secs
        ]);
    }
    table.print();

    println!("\n{} entry(ies) total.", entries.len());
    Ok(())
}

pub async fn cmd_ips_domain_blocks(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let entries = client.list_ips_domain_blocks().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    if entries.is_empty() {
        println!("No domain-based IPS blocks.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("IP", Align::Left),
        ("DOMAIN", Align::Left),
        ("SOURCE", Align::Left),
        ("TTL (s)", Align::Right),
    ]);

    for entry in &entries {
        table.row(cells![
            entry.ip,
            entry.domain,
            entry.source,
            entry.ttl_remaining_secs
        ]);
    }
    table.print();

    println!("\n{} entry(ies) total.", entries.len());
    Ok(())
}

pub async fn cmd_ips_set_mode(client: &ApiClient, id: &str, mode: &str) -> Result<()> {
    client.patch_ips_mode(id, mode).await?;
    println!("IPS rule {id} mode set to: {mode}");
    Ok(())
}

// ── Rate Limiting ───────────────────────────────────────────────────────

pub async fn cmd_ratelimit_list(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let rules = client.list_ratelimit_rules().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&rules)?);
        return Ok(());
    }

    if rules.is_empty() {
        println!("No rate limiting rules configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("SRC IP", Align::Left),
        ("RATE", Align::Right),
        ("BURST", Align::Right),
        ("ACTION", Align::Left),
        ("ALGORITHM", Align::Left),
        ("INTERFACES", Align::Left),
        ("ENABLED", Align::Left),
    ]);

    for rule in &rules {
        table.row(cells![
            rule.id,
            rule.src_ip,
            rule.rate,
            rule.burst,
            rule.action,
            rule.algorithm,
            interface_scope(&rule.interfaces),
            yes_no(rule.enabled)
        ]);
    }
    table.print();

    println!("\n{} rule(s) total.", rules.len());
    Ok(())
}

pub async fn cmd_ratelimit_add(client: &ApiClient, json: &str, output: OutputFormat) -> Result<()> {
    let body: serde_json::Value =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;
    let rule = client.create_ratelimit_rule(&body).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&rule)?);
        return Ok(());
    }

    println!(
        "Rate limit rule created: {} (src_ip={}, rate={}, burst={})",
        rule.id, rule.src_ip, rule.rate, rule.burst
    );
    Ok(())
}

pub async fn cmd_ratelimit_delete(client: &ApiClient, id: &str) -> Result<()> {
    client.delete_ratelimit_rule(id).await?;
    println!("Rate limit rule deleted: {id}");
    Ok(())
}

// ── Threat Intelligence ─────────────────────────────────────────────────

pub async fn cmd_threatintel_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.threatintel_status().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("Threat Intelligence Status");
    println!("  Enabled:    {}", yes_no(status.enabled));
    println!("  Mode:       {}", status.mode);
    println!("  IOC count:  {}", status.ioc_count);
    println!("  Feed count: {}", status.feed_count);
    Ok(())
}

pub async fn cmd_threatintel_iocs(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let iocs = client.list_iocs().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&iocs)?);
        return Ok(());
    }

    if iocs.is_empty() {
        println!("No IOCs loaded.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("IP", Align::Left),
        ("FEED ID", Align::Left),
        ("CONF", Align::Right),
        ("THREAT TYPE", Align::Left),
        ("SOURCE FEED", Align::Left),
    ]);

    for ioc in &iocs {
        table.row(cells![
            ioc.ip,
            ioc.feed_id,
            ioc.confidence,
            ioc.threat_type,
            ioc.source_feed
        ]);
    }
    table.print();

    println!("\n{} IOC(s) total.", iocs.len());
    Ok(())
}

pub async fn cmd_threatintel_feeds(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let feeds = client.list_feeds().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&feeds)?);
        return Ok(());
    }

    if feeds.is_empty() {
        println!("No feeds configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("NAME", Align::Left),
        ("FORMAT", Align::Left),
        ("ENABLED", Align::Left),
        ("REFRESH (s)", Align::Right),
        ("MAX IOCs", Align::Right),
        ("CONF", Align::Right),
    ]);

    for feed in &feeds {
        table.row(cells![
            feed.id,
            feed.name,
            feed.format,
            yes_no(feed.enabled),
            feed.refresh_interval_secs,
            feed.max_iocs,
            feed.min_confidence
        ]);
    }
    table.print();

    println!("\n{} feed(s) total.", feeds.len());
    Ok(())
}

// ── Alerts ──────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn cmd_alerts_list(
    client: &ApiClient,
    component: Option<&str>,
    severity: Option<&str>,
    tactic: Option<&str>,
    technique: Option<&str>,
    triage: &crate::api_client::TriageFilter,
    limit: u64,
    offset: u64,
    output: OutputFormat,
) -> Result<()> {
    let resp = client
        .list_alerts(
            component, severity, tactic, technique, triage, limit, offset,
        )
        .await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    if resp.alerts.is_empty() {
        println!("No alerts found.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("COMPONENT", Align::Left),
        ("SEVERITY", Align::Left),
        ("RULE ID", Align::Left),
        ("ACTION", Align::Left),
        ("SRC IP", Align::Left),
        ("DST IP", Align::Left),
        ("SPORT", Align::Right),
        ("DPORT", Align::Right),
        ("FP", Align::Left),
        ("SRC DOMAIN", Align::Left),
        ("DST DOMAIN", Align::Left),
        ("MESSAGE", Align::Left),
    ]);

    for alert in &resp.alerts {
        let msg = truncate(&alert.message, 48);
        let src_domain = alert.src_domain.as_deref().unwrap_or("-");
        let dst_domain = alert.dst_domain.as_deref().unwrap_or("-");
        table.row(cells![
            alert.id,
            alert.component,
            alert.severity,
            alert.rule_id,
            alert.action,
            alert.src_ip_str(),
            alert.dst_ip_str(),
            alert.src_port,
            alert.dst_port,
            if alert.false_positive { "yes" } else { "no" },
            src_domain,
            dst_domain,
            msg
        ]);
    }
    table.print();

    println!(
        "\nShowing {}/{} alert(s) (offset={}).",
        resp.alerts.len(),
        resp.total,
        resp.offset
    );
    Ok(())
}

pub async fn cmd_alerts_show(client: &ApiClient, id: &str, output: OutputFormat) -> Result<()> {
    let alert = client.get_alert(id).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&alert)?);
        return Ok(());
    }

    println!("Alert {}", alert.id);
    println!("  Component:      {}", alert.component);
    println!("  Severity:       {}", alert.severity);
    println!("  Rule:           {}", alert.rule_id);
    println!("  Action:         {}", alert.action);
    println!("  Timestamp (ns): {}", alert.timestamp_ns);
    println!(
        "  Source:         {}:{}",
        alert.src_ip_str(),
        alert.src_port
    );
    println!(
        "  Destination:    {}:{}",
        alert.dst_ip_str(),
        alert.dst_port
    );
    println!("  Protocol:       {}", alert.protocol);
    println!("  False positive: {}", yes_no(alert.false_positive));
    println!("  Status:         {}", alert.status);
    if let Some(who) = alert.assignee.as_deref() {
        println!("  Assignee:       {who}");
    }
    if let Some(domain) = alert.src_domain.as_deref() {
        println!("  Source domain:  {domain}");
    }
    if let Some(domain) = alert.dst_domain.as_deref() {
        println!("  Dest domain:    {domain}");
    }
    if let Some(geo) = alert.src_geo.as_deref() {
        println!("  Source country: {geo}");
    }
    if let Some(geo) = alert.dst_geo.as_deref() {
        println!("  Dest country:   {geo}");
    }
    if let Some(ja4) = alert.ja4_fingerprint.as_deref() {
        println!("  JA4:            {ja4}");
    }
    println!("  Message:        {}", alert.message);
    for note in &alert.notes {
        println!("  Note ({}): {}", note.author, note.text);
    }
    Ok(())
}

pub async fn cmd_alerts_triage(
    client: &ApiClient,
    ids: &[String],
    change: crate::api_client::TriageBody,
    output: OutputFormat,
) -> Result<()> {
    if let [id] = ids {
        let resp = client.triage_alert(id, &change).await?;
        if output == OutputFormat::Json {
            println!("{}", serde_json::to_string_pretty(&resp)?);
            return Ok(());
        }
        println!(
            "Alert {}: {}, {}, {} note(s)",
            resp.alert_id,
            resp.status,
            resp.assignee.as_deref().unwrap_or("unassigned"),
            resp.notes.len()
        );
        return Ok(());
    }

    let resp = client.triage_alerts(ids, &change).await?;
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }
    println!("{} alert(s) changed.", resp.updated.len());
    if !resp.missing.is_empty() {
        println!("No longer held: {}", resp.missing.join(", "));
    }
    Ok(())
}

pub async fn cmd_alerts_mark_fp(client: &ApiClient, id: &str, output: OutputFormat) -> Result<()> {
    let resp = client.mark_false_positive(id).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!(
        "Alert {} marked as false positive: {}",
        resp.alert_id, resp.marked
    );
    Ok(())
}

// ── Alert Stats ─────────────────────────────────────────────────────────

pub async fn cmd_alerts_stats(client: &ApiClient, limit: u64, output: OutputFormat) -> Result<()> {
    use std::collections::HashMap;

    let resp = client
        .list_alerts(
            None,
            None,
            None,
            None,
            &crate::api_client::ANY_TRIAGE,
            limit,
            0,
        )
        .await?;
    let alerts = &resp.alerts;

    // Severity distribution
    let mut by_severity: HashMap<&str, u64> = HashMap::new();
    // Component distribution
    let mut by_component: HashMap<&str, u64> = HashMap::new();
    // Top source IPs
    let mut by_src: HashMap<String, u64> = HashMap::new();
    // Top rules
    let mut by_rule: HashMap<&str, (&str, u64)> = HashMap::new();

    for a in alerts {
        *by_severity.entry(a.severity.as_str()).or_default() += 1;
        *by_component.entry(a.component.as_str()).or_default() += 1;
        *by_src.entry(a.src_ip_str()).or_default() += 1;
        let entry = by_rule
            .entry(a.rule_id.as_str())
            .or_insert((a.severity.as_str(), 0));
        entry.1 += 1;
    }

    if output == OutputFormat::Json {
        let json = serde_json::json!({
            "total": resp.total,
            "analyzed": alerts.len(),
            "by_severity": by_severity,
            "by_component": by_component,
            "top_sources": by_src,
            "top_rules": by_rule.iter().map(|(k, (sev, cnt))| {
                serde_json::json!({"rule_id": k, "severity": sev, "count": cnt})
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    let total = resp.total;
    let critical = by_severity.get("critical").copied().unwrap_or(0);
    let high = by_severity.get("high").copied().unwrap_or(0);
    let medium = by_severity.get("medium").copied().unwrap_or(0);
    let low = by_severity.get("low").copied().unwrap_or(0);

    println!();
    println!(
        "  Alerts: {total} total ({critical} critical, {high} high, {medium} medium, {low} low)"
    );
    println!();

    // Top sources
    let mut src_sorted: Vec<_> = by_src.iter().collect();
    src_sorted.sort_by(|a, b| b.1.cmp(a.1));
    let mut table =
        Table::new(&[("Top Sources", Align::Left), ("Alerts", Align::Right)]).indent("  ");
    for (ip, count) in src_sorted.iter().take(10) {
        table.row(cells![ip, count]);
    }
    table.print();
    println!();

    // Top rules
    let mut rule_sorted: Vec<_> = by_rule.iter().collect();
    rule_sorted.sort_by_key(|item| std::cmp::Reverse((item.1).1));
    let mut table = Table::new(&[
        ("Top Rules", Align::Left),
        ("Alerts", Align::Right),
        ("Severity", Align::Left),
    ])
    .indent("  ");
    for (rule, (severity, count)) in rule_sorted.iter().take(10) {
        table.row(cells![rule, count, severity]);
    }
    table.print();
    println!();

    // Component distribution
    let mut comp_sorted: Vec<_> = by_component.iter().collect();
    comp_sorted.sort_by(|a, b| b.1.cmp(a.1));
    let max_count = comp_sorted.first().map_or(1, |&(_, &c)| c);
    let mut table = Table::new(&[
        ("Components", Align::Left),
        ("Alerts", Align::Right),
        ("", Align::Left),
    ])
    .indent("  ");
    for &(comp, &count) in &comp_sorted {
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let bar_len = ((count as f64 / max_count as f64) * 20.0) as usize;
        let bar: String = "\u{2588}".repeat(bar_len);
        table.row(cells![comp, count, bar]);
    }
    table.print();
    println!();

    Ok(())
}

// ── Audit ───────────────────────────────────────────────────────────────

// ── MITRE ATT&CK ────────────────────────────────────────────────────

pub async fn cmd_mitre_coverage(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.mitre_coverage().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("MITRE ATT&CK Coverage ({})", resp.attack_version);
    println!("Total techniques covered: {}\n", resp.total_techniques);

    let mut table = Table::new(&[
        ("COMPONENT", Align::Left),
        ("TECHNIQUE", Align::Left),
        ("NAME", Align::Left),
        ("TACTIC", Align::Left),
        ("DESCRIPTION", Align::Left),
    ]);

    for t in &resp.techniques {
        table.row(cells![
            t.component,
            t.technique_id,
            t.technique_name,
            t.tactic,
            t.description
        ]);
    }
    table.print();

    println!("\n── Coverage by tactic ──");
    for t in &resp.by_tactic {
        println!(
            "  {:<22}  {} technique(s)  [{}]",
            t.tactic,
            t.covered_techniques,
            t.components.join(", "),
        );
    }

    Ok(())
}

// ── Captures ────────────────────────────────────────────────────────

pub async fn cmd_capture_start(
    client: &ApiClient,
    filter: &str,
    duration: &str,
    snap_length: u32,
    interface: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let duration_secs = parse_duration_secs(duration)?;
    let resp = client
        .start_capture(filter, duration_secs, snap_length, interface)
        .await?;
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        println!(
            "Capture started: {} (filter: {}, duration: {}s, output: {})",
            resp.id, resp.filter, resp.duration_secs, resp.output_path,
        );
    }
    Ok(())
}

pub async fn cmd_capture_stop(client: &ApiClient, id: &str, output: OutputFormat) -> Result<()> {
    let resp = client.stop_capture(id).await?;
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        println!("Capture {} stopped.", resp.id);
    }
    Ok(())
}

pub async fn cmd_capture_list(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.list_captures().await?;
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }
    if resp.captures.is_empty() {
        println!("No capture sessions.");
        return Ok(());
    }
    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("STATUS", Align::Left),
        ("FILTER", Align::Left),
        ("DURATION", Align::Right),
        ("SIZE", Align::Right),
        ("OUTPUT", Align::Left),
    ]);
    for c in &resp.captures {
        table.row(cells![
            c.id,
            c.status,
            truncate(&c.filter, 40),
            format!("{}s", c.duration_secs),
            format!("{}B", c.file_size_bytes),
            c.output_path
        ]);
    }
    table.print();
    Ok(())
}

fn parse_duration_secs(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix('s') {
        (n, 1u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else {
        (s, 1)
    };
    let val: u64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration: {s}"))?;
    Ok(val * mult)
}

// ── Responses ───────────────────────────────────────────────────────

pub async fn cmd_responses_list(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.list_responses().await?;
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }
    if resp.actions.is_empty() {
        println!("No active response actions.");
        return Ok(());
    }
    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("ACTION", Align::Left),
        ("TARGET", Align::Left),
        ("TTL", Align::Right),
        ("REMAINING", Align::Right),
        ("REVOKED", Align::Left),
    ]);
    for a in &resp.actions {
        table.row(cells![
            a.id,
            a.action_type,
            a.target,
            format!("{}s", a.ttl_secs),
            format!("{}s", a.remaining_secs),
            a.revoked
        ]);
    }
    table.print();
    println!("\n{} active action(s).", resp.active_count);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn cmd_responses_create(
    client: &ApiClient,
    action: &str,
    target: &str,
    ttl: &str,
    rate_pps: Option<u64>,
    output: OutputFormat,
) -> Result<()> {
    let resp = client
        .create_response(action, target, ttl, rate_pps)
        .await?;
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        println!(
            "Response action created: {} → {} {} (TTL: {}s, rule: {})",
            resp.id, resp.action_type, resp.target, resp.ttl_secs, resp.rule_id,
        );
    }
    Ok(())
}

pub async fn cmd_responses_revoke(
    client: &ApiClient,
    id: &str,
    output: OutputFormat,
) -> Result<()> {
    let resp = client.revoke_response(id).await?;
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        println!("Response action {} revoked.", resp.id);
    }
    Ok(())
}

// ── Fingerprints ────────────────────────────────────────────────────

pub async fn cmd_fingerprints_summary(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.fingerprint_summary().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("JA4+ Fingerprint Cache");
    println!("  Cached entries:  {}", resp.cached_count);
    println!("  Max size:        {}", resp.max_size);
    println!("  TTL:             {}s", resp.ttl_seconds);
    // The server-side listing says this and this one did not, so a cache that
    // fell back to memory because its store would not open read as persistent
    // on one command and said nothing on the other.
    println!("  Persistent:      {}", yes_no(resp.persistent));

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn cmd_audit_logs(
    client: &ApiClient,
    component: Option<&str>,
    action: Option<&str>,
    limit: u64,
    offset: u64,
    output: OutputFormat,
) -> Result<()> {
    let resp = client
        .list_audit_logs(component, action, limit, offset)
        .await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    if resp.entries.is_empty() {
        println!("No audit log entries found.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("COMPONENT", Align::Left),
        ("ACTION", Align::Left),
        ("SRC IP", Align::Left),
        ("DST IP", Align::Left),
        ("SPORT", Align::Right),
        ("DPORT", Align::Right),
        ("RULE ID", Align::Left),
        ("DETAIL", Align::Left),
    ]);

    for entry in &resp.entries {
        let detail = truncate(&entry.detail, 48);
        table.row(cells![
            entry.component,
            entry.action,
            entry.src_ip_str(),
            entry.dst_ip_str(),
            entry.src_port,
            entry.dst_port,
            entry.rule_id,
            detail
        ]);
    }
    table.print();

    println!(
        "\nShowing {}/{} entry(ies) (offset={}).",
        resp.entries.len(),
        resp.total,
        resp.offset
    );
    Ok(())
}

pub async fn cmd_audit_history(client: &ApiClient, id: &str, output: OutputFormat) -> Result<()> {
    let resp = client.rule_history(id).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    if resp.entries.is_empty() {
        println!("No history for rule {id}.");
        return Ok(());
    }

    println!("Rule history for: {}", resp.rule_id);
    let mut table = Table::new(&[
        ("VER", Align::Right),
        ("ACTION", Align::Left),
        ("COMPONENT", Align::Left),
        ("ACTOR", Align::Left),
        ("AFTER", Align::Left),
    ]);

    for entry in &resp.entries {
        let after = entry.after.as_deref().unwrap_or("-");
        let after_display = if after.len() > 40 {
            format!("{}...", &after[..37])
        } else {
            after.to_string()
        };
        table.row(cells![
            entry.version,
            entry.action,
            entry.component,
            entry.actor,
            after_display
        ]);
    }
    table.print();

    println!("\n{} version(s).", resp.entries.len());
    Ok(())
}

// ── DNS Intelligence ────────────────────────────────────────────────────

pub async fn cmd_dns_cache(
    client: &ApiClient,
    domain: Option<&str>,
    ip: Option<&str>,
    page: usize,
    page_size: usize,
    output: OutputFormat,
) -> Result<()> {
    let resp = client.dns_cache(domain, ip, page, page_size).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    if resp.entries.is_empty() {
        println!("No DNS cache entries found.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("DOMAIN", Align::Left),
        ("IPs", Align::Left),
        ("TTL (s)", Align::Right),
        ("QUERIES", Align::Right),
        ("BLOCKED", Align::Left),
    ]);

    for entry in &resp.entries {
        let ips_display = truncate(&entry.ips.join(", "), 40);
        table.row(cells![
            entry.domain,
            ips_display,
            entry.ttl_remaining_secs,
            entry.query_count,
            yes_no(entry.is_blocked)
        ]);
    }
    table.print();

    println!(
        "\nPage {}, {} entry(ies) shown.",
        resp.page,
        resp.entries.len()
    );
    Ok(())
}

pub async fn cmd_dns_stats(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let stats = client.dns_stats().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&stats)?);
        return Ok(());
    }

    println!("DNS Intelligence Statistics");
    println!("  Cache entries:        {}", stats.total_entries);
    println!("  Cache hits:           {}", stats.hit_count);
    println!("  Cache misses:         {}", stats.miss_count);
    println!("  Evictions:            {}", stats.eviction_count);
    println!("  Expired:              {}", stats.expired_count);
    println!("  Blocklist patterns:   {}", stats.blocklist_pattern_count);
    println!(
        "  Domains blocked:      {}",
        stats.blocklist_domains_blocked
    );
    println!("  IPs injected:         {}", stats.blocklist_ips_injected);

    if !stats.top_queried.is_empty() {
        println!("\nTop queried domains:");
        let mut table =
            Table::new(&[("DOMAIN", Align::Left), ("QUERIES", Align::Right)]).indent("  ");
        for entry in &stats.top_queried {
            table.row(cells![entry.domain, entry.query_count]);
        }
        table.print();
    }

    Ok(())
}

pub async fn cmd_dns_blocklist(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let rules = client.dns_blocklist().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&rules)?);
        return Ok(());
    }

    if rules.is_empty() {
        println!("No blocklist rules loaded.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("PATTERN", Align::Left),
        ("ACTION", Align::Left),
        ("MATCHES", Align::Right),
    ]);

    for rule in &rules {
        table.row(cells![
            truncate(&rule.pattern, 40),
            rule.action,
            rule.match_count
        ]);
    }
    table.print();

    println!("\n{} rule(s) total.", rules.len());
    Ok(())
}

pub async fn cmd_dns_flush(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.dns_flush().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!(
        "DNS cache flushed: {} entries removed.",
        resp.flushed_entries
    );
    Ok(())
}

// ── Domain Intelligence ──────────────────────────────────────────────────

pub async fn cmd_domains_reputation(
    client: &ApiClient,
    domain: Option<&str>,
    min_score: Option<f64>,
    page: usize,
    page_size: usize,
    output: OutputFormat,
) -> Result<()> {
    let resp = client
        .list_domain_reputations(domain, min_score, page, page_size)
        .await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    if resp.entries.is_empty() {
        println!("No domain reputations found.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("DOMAIN", Align::Left),
        ("SCORE", Align::Right),
        ("FACTORS", Align::Left),
        ("BLOCKED", Align::Left),
    ]);

    for entry in &resp.entries {
        let factors = if entry.factors.is_empty() {
            "-".to_string()
        } else {
            entry.factors.join(", ")
        };
        table.row(cells![
            entry.domain,
            format!("{:.3}", entry.score),
            truncate(&factors, 40),
            yes_no(entry.is_blocked)
        ]);
    }
    table.print();

    println!(
        "\nPage {}, {} entry(ies) shown.",
        resp.page,
        resp.entries.len()
    );
    Ok(())
}

pub async fn cmd_domains_block(
    client: &ApiClient,
    domain: &str,
    output: OutputFormat,
) -> Result<()> {
    let resp = client.domain_block(domain).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("Domain added to blocklist: {}", resp.domain);
    Ok(())
}

pub async fn cmd_domains_unblock(
    client: &ApiClient,
    domain: &str,
    output: OutputFormat,
) -> Result<()> {
    let resp = client.domain_unblock(domain).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("Domain removed from blocklist: {}", resp.domain);
    Ok(())
}

// ── DDoS Protection ────────────────────────────────────────────────────

pub async fn cmd_ddos_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.ddos_status().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("DDoS Protection Status");
    println!("  Enabled:          {}", yes_no(status.enabled));
    println!("  Active attacks:   {}", status.active_attacks);
    println!("  Total mitigated:  {}", status.total_mitigated);
    println!("  Policy count:     {}", status.policy_count);
    Ok(())
}

pub async fn cmd_ddos_attacks(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let attacks = client.ddos_attacks().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&attacks)?);
        return Ok(());
    }

    if attacks.is_empty() {
        println!("No active DDoS attacks.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("ATTACK TYPE", Align::Left),
        ("STATUS", Align::Left),
        ("COUNTRY", Align::Left),
        ("PEAK PPS", Align::Right),
        ("CUR PPS", Align::Right),
        ("TOTAL PKTS", Align::Right),
        ("SOURCES", Align::Right),
    ]);

    for a in &attacks {
        table.row(cells![
            a.id,
            a.attack_type,
            a.status,
            a.src_country.as_deref().unwrap_or("-"),
            a.peak_pps,
            a.current_pps,
            a.total_packets,
            a.source_count
        ]);
    }
    table.print();

    println!("\n{} active attack(s).", attacks.len());
    Ok(())
}

pub async fn cmd_ddos_history(
    client: &ApiClient,
    limit: usize,
    output: OutputFormat,
) -> Result<()> {
    let attacks = client.ddos_history(limit).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&attacks)?);
        return Ok(());
    }

    if attacks.is_empty() {
        println!("No DDoS attack history.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("ATTACK TYPE", Align::Left),
        ("STATUS", Align::Left),
        ("COUNTRY", Align::Left),
        ("PEAK PPS", Align::Right),
        ("CUR PPS", Align::Right),
        ("TOTAL PKTS", Align::Right),
        ("SOURCES", Align::Right),
    ]);

    for a in &attacks {
        table.row(cells![
            a.id,
            a.attack_type,
            a.status,
            a.src_country.as_deref().unwrap_or("-"),
            a.peak_pps,
            a.current_pps,
            a.total_packets,
            a.source_count
        ]);
    }
    table.print();

    println!("\n{} historical attack(s).", attacks.len());
    Ok(())
}

pub async fn cmd_ddos_policies(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let policies = client.ddos_policies().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&policies)?);
        return Ok(());
    }

    if policies.is_empty() {
        println!("No DDoS policies configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("ATTACK TYPE", Align::Left),
        ("THRESH PPS", Align::Right),
        ("ACTION", Align::Left),
        ("BLOCK (s)", Align::Right),
        ("ENABLED", Align::Left),
        ("COUNTRIES", Align::Right),
    ]);

    for p in &policies {
        // The per-country thresholds are a map: the table says how many
        // there are, since a policy firing under its own threshold is
        // explained by one of them, and `--output json` carries them in full.
        let countries = p
            .country_thresholds
            .as_ref()
            .map_or(0, std::collections::HashMap::len);
        table.row(cells![
            p.id,
            p.attack_type,
            p.detection_threshold_pps,
            p.mitigation_action,
            p.auto_block_duration_secs,
            yes_no(p.enabled),
            countries
        ]);
    }
    table.print();

    println!("\n{} policy(ies) total.", policies.len());
    Ok(())
}

pub async fn cmd_ddos_add(client: &ApiClient, json: &str, output: OutputFormat) -> Result<()> {
    let body: serde_json::Value =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;
    let policy = client.create_ddos_policy(&body).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&policy)?);
        return Ok(());
    }

    println!(
        "DDoS policy created: {} (type={}, action={}, threshold={})",
        policy.id, policy.attack_type, policy.mitigation_action, policy.detection_threshold_pps
    );
    Ok(())
}

pub async fn cmd_ddos_delete(client: &ApiClient, id: &str) -> Result<()> {
    client.delete_ddos_policy(id).await?;
    println!("DDoS policy deleted: {id}");
    Ok(())
}

// ── Load Balancer ──────────────────────────────────────────────────────

pub async fn cmd_lb_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.lb_status().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("Load Balancer Status");
    println!("  Enabled:       {}", yes_no(status.enabled));
    println!("  Service count: {}", status.service_count);
    Ok(())
}

pub async fn cmd_lb_services(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let services = client.list_lb_services().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&services)?);
        return Ok(());
    }

    if services.is_empty() {
        println!("No load balancer services configured.");
        return Ok(());
    }

    // MODE decides whether the reply leaves through the balancer at all, and
    // PROBED says whether the statuses on the detail screen were measured.
    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("NAME", Align::Left),
        ("PROTO", Align::Left),
        ("PORT", Align::Right),
        ("ALGORITHM", Align::Left),
        ("MODE", Align::Left),
        ("BACKENDS", Align::Right),
        ("PROBED", Align::Left),
        ("ENABLED", Align::Left),
    ]);

    for svc in &services {
        table.row(cells![
            svc.id,
            svc.name,
            svc.protocol,
            svc.listen_port,
            svc.algorithm,
            svc.mode,
            svc.backend_count,
            yes_no(svc.health_checked),
            yes_no(svc.enabled)
        ]);
    }
    table.print();

    println!("\n{} service(s) total.", services.len());
    Ok(())
}

pub async fn cmd_lb_service(client: &ApiClient, id: &str, output: OutputFormat) -> Result<()> {
    let svc = client.get_lb_service(id).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&svc)?);
        return Ok(());
    }

    println!("Service: {} ({})", svc.name, svc.id);
    println!("  Protocol:  {}", svc.protocol);
    println!("  Port:      {}", svc.listen_port);
    println!("  Algorithm: {}", svc.algorithm);
    println!("  Mode:      {}", svc.mode);
    println!("  Enabled:   {}", yes_no(svc.enabled));
    // A backend nothing probes keeps the status it was created with, so the
    // probe has to be named beside the statuses it did or did not produce.
    match &svc.health_check {
        Some(hc) => println!(
            "  Health:    {} every {}s, timeout {}s, {} failure(s) to fail, {} to recover",
            hc.protocol,
            hc.interval_secs,
            hc.timeout_secs,
            hc.failure_threshold,
            hc.recovery_threshold,
        ),
        None => println!("  Health:    none - every backend below reads healthy by default"),
    }

    if svc.backends.is_empty() {
        println!("\n  No backends.");
    } else {
        println!();
        let mut table = Table::new(&[
            ("BACKEND", Align::Left),
            ("ADDR", Align::Left),
            ("PORT", Align::Right),
            ("WEIGHT", Align::Right),
            ("SAME-SEG", Align::Left),
            ("STATUS", Align::Left),
            ("PROBED", Align::Left),
            ("CONNS", Align::Right),
            ("ENABLED", Align::Left),
        ])
        .indent("  ");
        for be in &svc.backends {
            table.row(cells![
                be.id,
                be.addr,
                be.port,
                be.weight,
                yes_no(be.same_segment),
                be.status,
                yes_no(be.probed),
                be.active_connections,
                yes_no(be.enabled)
            ]);
        }
        table.print();
        println!("\n  {} backend(s) total.", svc.backends.len());
    }
    Ok(())
}

pub async fn cmd_lb_add(client: &ApiClient, json: &str, output: OutputFormat) -> Result<()> {
    let body: serde_json::Value =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;
    let svc = client.create_lb_service(&body).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&svc)?);
        return Ok(());
    }

    println!(
        "LB service created: {} (protocol={}, port={}, algorithm={})",
        svc.id, svc.protocol, svc.listen_port, svc.algorithm
    );
    Ok(())
}

pub async fn cmd_lb_delete(client: &ApiClient, id: &str) -> Result<()> {
    client.delete_lb_service(id).await?;
    println!("LB service deleted: {id}");
    Ok(())
}

pub async fn cmd_lb_vips(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.list_lb_vips().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("L2 VIP Announcer");
    println!("  Role:           {}", status.role);
    println!("  Interface:      {}", status.interface);
    println!("  Speaker:        {}", yes_no(status.is_speaker));
    println!("  Bindings count: {}", status.bindings_count);

    if status.vips.is_empty() {
        println!("\n  No VIPs configured.");
        return Ok(());
    }

    println!();
    let mut table = Table::new(&[
        ("NAME", Align::Left),
        ("ADDR", Align::Left),
        ("ARP_REPLIES", Align::Right),
        ("ANNOUNCED", Align::Left),
    ])
    .indent("  ");
    for vip in &status.vips {
        table.row(cells![
            vip.name,
            vip.addr,
            vip.arp_replies,
            yes_no(vip.self_announced)
        ]);
    }
    table.print();
    println!("\n  {} VIP(s) total.", status.vips.len());
    Ok(())
}

pub async fn cmd_lb_announce(client: &ApiClient, json: &str, output: OutputFormat) -> Result<()> {
    let body: serde_json::Value =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;
    let status = client.apply_lb_announce(&body).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!(
        "VIP announce config applied: role={}, interface={}, vips={}",
        status.role,
        status.interface,
        status.vips.len()
    );
    Ok(())
}

// ── QoS ─────────────────────────────────────────────────────────────

pub async fn cmd_qos_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.qos_status().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("QoS / Traffic Shaping Status");
    println!("  Enabled:          {}", yes_no(status.enabled));
    println!("  Pipe count:       {}", status.pipe_count);
    println!("  Queue count:      {}", status.queue_count);
    println!("  Classifier count: {}", status.classifier_count);
    Ok(())
}

pub async fn cmd_qos_pipes(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let pipes = client.list_qos_pipes().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&pipes)?);
        return Ok(());
    }

    if pipes.is_empty() {
        println!("No QoS pipes configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("RATE (bps)", Align::Right),
        ("BURST (bytes)", Align::Right),
        ("DIR", Align::Left),
        ("DELAY(ms)", Align::Right),
        ("LOSS(%)", Align::Right),
        ("INTERFACES", Align::Left),
        ("STATE", Align::Left),
    ]);

    for pipe in &pipes {
        table.row(cells![
            pipe.id,
            pipe.rate_bps,
            pipe.burst_bytes,
            pipe.direction,
            pipe.delay_ms,
            format!("{:.2}", pipe.loss_pct),
            interface_scope(&pipe.interfaces),
            if pipe.enabled { "enabled" } else { "disabled" }
        ]);
    }
    table.print();

    println!("\n{} pipe(s) total.", pipes.len());
    Ok(())
}

pub async fn cmd_qos_queues(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let queues = client.list_qos_queues().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&queues)?);
        return Ok(());
    }

    if queues.is_empty() {
        println!("No QoS queues configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("PIPE ID", Align::Left),
        ("STATE", Align::Left),
    ]);

    for queue in &queues {
        table.row(cells![
            queue.id,
            queue.pipe_id,
            if queue.enabled { "enabled" } else { "disabled" }
        ]);
    }
    table.print();

    println!("\n{} queue(s) total.", queues.len());
    Ok(())
}

pub async fn cmd_qos_classifiers(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let classifiers = client.list_qos_classifiers().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&classifiers)?);
        return Ok(());
    }

    if classifiers.is_empty() {
        println!("No QoS classifiers configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("QUEUE ID", Align::Left),
        ("PRI", Align::Right),
        ("INTERFACES", Align::Left),
    ]);

    for cls in &classifiers {
        table.row(cells![
            cls.id,
            cls.queue_id,
            cls.priority,
            interface_scope(&cls.interfaces)
        ]);
    }
    table.print();

    println!("\n{} classifier(s) total.", classifiers.len());
    Ok(())
}

pub async fn cmd_qos_add_pipe(client: &ApiClient, json: &str, output: OutputFormat) -> Result<()> {
    let body: serde_json::Value =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;
    let pipe = client.create_qos_pipe(&body).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&pipe)?);
        return Ok(());
    }

    println!(
        "QoS pipe created: {} (rate={}, burst={})",
        pipe.id, pipe.rate_bps, pipe.burst_bytes
    );
    Ok(())
}

pub async fn cmd_qos_delete_pipe(client: &ApiClient, id: &str) -> Result<()> {
    client.delete_qos_pipe(id).await?;
    println!("QoS pipe deleted: {id}");
    Ok(())
}

pub async fn cmd_qos_add_queue(client: &ApiClient, json: &str, output: OutputFormat) -> Result<()> {
    let body: serde_json::Value =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;
    let queue = client.create_qos_queue(&body).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&queue)?);
        return Ok(());
    }

    println!("QoS queue created: {} (pipe={})", queue.id, queue.pipe_id);
    Ok(())
}

pub async fn cmd_qos_delete_queue(client: &ApiClient, id: &str) -> Result<()> {
    client.delete_qos_queue(id).await?;
    println!("QoS queue deleted: {id}");
    Ok(())
}

pub async fn cmd_qos_add_classifier(
    client: &ApiClient,
    json: &str,
    output: OutputFormat,
) -> Result<()> {
    let body: serde_json::Value =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;
    let cls = client.create_qos_classifier(&body).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&cls)?);
        return Ok(());
    }

    println!(
        "QoS classifier created: {} (queue={}, priority={})",
        cls.id, cls.queue_id, cls.priority
    );
    Ok(())
}

pub async fn cmd_qos_delete_classifier(client: &ApiClient, id: &str) -> Result<()> {
    client.delete_qos_classifier(id).await?;
    println!("QoS classifier deleted: {id}");
    Ok(())
}

// ── Watch ───────────────────────────────────────────────────────────

/// First wait between reconnect attempts, so a restarting agent is picked up
/// again straight away.
const RECONNECT_BACKOFF_START_SECS: u64 = 1;
/// Ceiling the wait doubles up to, so an agent that is down is not hammered.
const RECONNECT_BACKOFF_MAX_SECS: u64 = 30;

fn next_backoff(current: std::time::Duration) -> std::time::Duration {
    let doubled = current.as_secs().saturating_mul(2);
    std::time::Duration::from_secs(doubled.min(RECONNECT_BACKOFF_MAX_SECS))
}

fn backoff_start() -> std::time::Duration {
    std::time::Duration::from_secs(RECONNECT_BACKOFF_START_SECS)
}

/// One alert, printed the same way whether it arrived on the stream or came
/// back from the paged list.
fn print_alert_line(alert: &AlertResponse) {
    // The stream serialises the agent's own record, where a severity is
    // `High`; the list endpoint lowercases it on the way out. Print one
    // spelling either way, so a fallback does not look like another agent.
    let severity = alert.severity.to_ascii_lowercase();
    let severity = match severity.as_str() {
        "critical" => format!("\x1b[91m{severity:<8}\x1b[0m"),
        "high" => format!("\x1b[93m{severity:<8}\x1b[0m"),
        "medium" => format!("\x1b[33m{severity:<8}\x1b[0m"),
        _ => format!("{severity:<8}"),
    };

    println!(
        "  {:<12}  {}  {:<18} -> {:<18}  {}",
        alert.component,
        severity,
        alert.src_ip_str(),
        alert.dst_ip_str(),
        truncate(&alert.message, 50),
    );
}

pub async fn cmd_watch(
    client: &ApiClient,
    interval_secs: u64,
    component: Option<&str>,
    severity: Option<&str>,
) -> Result<()> {
    let filter_desc = match (component, severity) {
        (Some(c), Some(s)) => format!(" (component={c}, severity>={s})"),
        (Some(c), None) => format!(" (component={c})"),
        (None, Some(s)) => format!(" (severity>={s})"),
        _ => String::new(),
    };
    eprintln!("Watching alerts{filter_desc} - live stream. Press Ctrl+C to stop.\n");

    // The id of the last alert printed. A reconnect hands it back so the
    // agent replays what happened while the connection was down.
    let mut resume_from: Option<String> = None;
    let mut backoff = backoff_start();

    loop {
        match client
            .stream_alerts(component, severity, resume_from.as_deref())
            .await
        {
            Ok(mut stream) => {
                backoff = backoff_start();
                loop {
                    match stream.next_event().await {
                        Ok(Some(event)) => match serde_json::from_str::<AlertResponse>(&event.data)
                        {
                            Ok(alert) => print_alert_line(&alert),
                            Err(e) => eprintln!("  [skipped] unreadable alert frame: {e}"),
                        },
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("  [stream] {e}");
                            break;
                        }
                    }
                }
                resume_from = stream.last_event_id().map(ToString::to_string);
            }
            Err(StreamOpenError::NotAvailable { message }) => {
                eprintln!(
                    "  [polling] this agent serves no alert stream ({message}); \
                     polling every {interval_secs}s instead, so an alert can be \
                     up to that late."
                );
                return watch_alerts_by_polling(client, interval_secs, component, severity).await;
            }
            Err(StreamOpenError::Failed(e)) => eprintln!("  [stream] {e}"),
        }

        eprintln!("  [stream] reconnecting in {}s", backoff.as_secs());
        tokio::time::sleep(backoff).await;
        backoff = next_backoff(backoff);
    }
}

/// What `watch` falls back to where the agent serves no alert stream: the
/// paged list, re-read on an interval, with the ids already printed
/// remembered so nothing is shown twice.
async fn watch_alerts_by_polling(
    client: &ApiClient,
    interval_secs: u64,
    component: Option<&str>,
    severity: Option<&str>,
) -> Result<()> {
    use std::collections::HashSet;

    let interval = std::time::Duration::from_secs(interval_secs.max(1));
    let mut seen: HashSet<String> = HashSet::new();

    // Seed with existing alerts so we only show new ones
    if let Ok(resp) = client
        .list_alerts(
            component,
            severity,
            None,
            None,
            &crate::api_client::ANY_TRIAGE,
            100,
            0,
        )
        .await
    {
        for a in &resp.alerts {
            seen.insert(a.id.clone());
        }
    }

    loop {
        tokio::time::sleep(interval).await;

        let resp = match client
            .list_alerts(
                component,
                severity,
                None,
                None,
                &crate::api_client::ANY_TRIAGE,
                50,
                0,
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  [error] {e}");
                continue;
            }
        };

        // Show alerts we haven't seen yet (newest first in API, reverse to print oldest first)
        let mut new_alerts: Vec<_> = resp
            .alerts
            .iter()
            .filter(|a| !seen.contains(&a.id))
            .collect();
        new_alerts.reverse();

        for a in &new_alerts {
            seen.insert(a.id.clone());
            print_alert_line(a);
        }
    }
}

// ── Top Talkers ─────────────────────────────────────────────────────

pub async fn cmd_top(
    client: &ApiClient,
    limit: usize,
    sort: &str,
    output: OutputFormat,
) -> Result<()> {
    let mut conns = client.list_connections(limit.max(500)).await?;

    if output == OutputFormat::Json {
        conns.truncate(limit);
        println!("{}", serde_json::to_string_pretty(&conns)?);
        return Ok(());
    }

    // Sort by requested field (descending)
    match sort {
        "packets" => conns.sort_by(|a, b| {
            let ta = u64::from(a.packets_fwd) + u64::from(a.packets_rev);
            let tb = u64::from(b.packets_fwd) + u64::from(b.packets_rev);
            tb.cmp(&ta)
        }),
        _ => conns.sort_by(|a, b| {
            let ta = u64::from(a.bytes_fwd) + u64::from(a.bytes_rev);
            let tb = u64::from(b.bytes_fwd) + u64::from(b.bytes_rev);
            tb.cmp(&ta)
        }),
    }

    conns.truncate(limit);

    if conns.is_empty() {
        println!("No active connections.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("SOURCE", Align::Left),
        ("PORT", Align::Right),
        ("DESTINATION", Align::Left),
        ("PORT", Align::Right),
        ("PROTO", Align::Left),
        ("STATE", Align::Left),
        ("BYTES", Align::Right),
        ("PACKETS", Align::Right),
    ]);

    for c in &conns {
        let total_bytes = u64::from(c.bytes_fwd) + u64::from(c.bytes_rev);
        let total_pkts = u64::from(c.packets_fwd) + u64::from(c.packets_rev);
        let proto = match c.protocol {
            6 => "TCP",
            17 => "UDP",
            1 => "ICMP",
            58 => "ICMPv6",
            _ => "OTHER",
        };
        table.row(cells![
            c.src_ip,
            c.src_port,
            c.dst_ip,
            c.dst_port,
            proto,
            c.state,
            format_bytes(total_bytes),
            total_pkts,
        ]);
    }
    table.print();

    println!("\n{} connection(s) shown (sorted by {sort}).", conns.len());
    Ok(())
}

// ── Flows ───────────────────────────────────────────────────────────

pub async fn cmd_flows(client: &ApiClient, limit: usize, output: OutputFormat) -> Result<()> {
    use std::collections::HashMap;

    let conns = client.list_connections(limit).await?;

    // Aggregate by (src_subnet, dst_subnet, dst_port, protocol)
    // Use /24 for IPv4, /48 for IPv6
    let mut agg: HashMap<String, FlowAgg> = HashMap::new();
    for c in &conns {
        let src_net = subnet_of(&c.src_ip);
        let dst_net = subnet_of(&c.dst_ip);
        let proto = match c.protocol {
            6 => "TCP",
            17 => "UDP",
            1 => "ICMP",
            58 => "ICMPv6",
            _ => "OTHER",
        };
        let key = format!("{src_net} -> {dst_net}:{} ({proto})", c.dst_port);
        let entry = agg.entry(key).or_insert(FlowAgg {
            flows: 0,
            bytes: 0,
            packets: 0,
        });
        entry.flows += 1;
        entry.bytes += u64::from(c.bytes_fwd) + u64::from(c.bytes_rev);
        entry.packets += u64::from(c.packets_fwd) + u64::from(c.packets_rev);
    }

    let mut sorted: Vec<(String, FlowAgg)> = agg.into_iter().collect();
    sorted.sort_by_key(|item| std::cmp::Reverse(item.1.bytes));

    if output == OutputFormat::Json {
        let json_flows: Vec<serde_json::Value> = sorted
            .iter()
            .map(|(k, v)| {
                serde_json::json!({
                    "flow": k,
                    "connections": v.flows,
                    "bytes": v.bytes,
                    "packets": v.packets,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json_flows)?);
        return Ok(());
    }

    if sorted.is_empty() {
        println!("No active flows.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("FLOW", Align::Left),
        ("CONNS", Align::Right),
        ("BYTES", Align::Right),
        ("PACKETS", Align::Right),
    ]);

    for (key, agg) in &sorted {
        table.row(cells![key, agg.flows, format_bytes(agg.bytes), agg.packets]);
    }
    table.print();

    println!(
        "\n{} aggregated flow(s) from {} connection(s).",
        sorted.len(),
        conns.len()
    );
    Ok(())
}

// ── Conntrack ──────────────────────────────────────────────────────────

pub async fn cmd_conntrack_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.conntrack_status().await?;
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        let count = resp
            .connection_count
            .map_or_else(|| "unknown".to_string(), |c| c.to_string());
        println!(
            "enabled: {}\nconnections: {} / {}",
            resp.enabled, count, resp.max_connections
        );
    }
    Ok(())
}

pub async fn cmd_conntrack_list(
    client: &ApiClient,
    limit: usize,
    output: OutputFormat,
) -> Result<()> {
    let conns = client.list_connections(limit).await?;
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&conns)?);
    } else {
        let mut table = Table::new(&[
            ("SRC", Align::Left),
            ("DST", Align::Left),
            ("SPORT", Align::Right),
            ("DPORT", Align::Right),
            ("PROTO", Align::Right),
            ("STATE", Align::Right),
            ("PKT_FWD", Align::Right),
            ("PKT_REV", Align::Right),
        ]);
        for c in &conns {
            table.row(cells![
                c.src_ip,
                c.dst_ip,
                c.src_port,
                c.dst_port,
                c.protocol,
                c.state,
                c.packets_fwd,
                c.packets_rev
            ]);
        }
        table.print();
        println!("total: {}", conns.len());
    }
    Ok(())
}

/// The five-tuple a flow is printed under, identical on the stream and on
/// the polled fallback so one line means the same thing either way.
fn conntrack_key(c: &ConnectionResponse) -> String {
    format!(
        "{}:{}-{}:{}/{}",
        c.src_ip, c.src_port, c.dst_ip, c.dst_port, c.protocol,
    )
}

fn print_conntrack_line(kind: &str, key: &str, state: Option<&str>) {
    let kind = kind.to_uppercase();
    let now = chrono_or_now();
    match state {
        Some(state) => println!("[{kind}] {now} {key} state={state}"),
        None => println!("[{kind}] {now} {key}"),
    }
}

pub async fn cmd_conntrack_watch(client: &ApiClient, interval: u64) -> Result<()> {
    eprintln!("Watching conntrack events - live stream. Press Ctrl+C to stop.");

    let mut backoff = backoff_start();

    loop {
        match client.stream_conntrack_events().await {
            Ok(mut stream) => {
                backoff = backoff_start();
                loop {
                    match stream.next_event().await {
                        Ok(Some(event)) => {
                            match serde_json::from_str::<ConntrackEventFrame>(&event.data) {
                                Ok(frame) => print_conntrack_line(
                                    &frame.event_type,
                                    &conntrack_key(&frame.connection),
                                    Some(&frame.connection.state),
                                ),
                                Err(e) => {
                                    eprintln!("  [skipped] unreadable conntrack frame: {e}");
                                }
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("  [stream] {e}");
                            break;
                        }
                    }
                }
            }
            Err(StreamOpenError::NotAvailable { message }) => {
                eprintln!(
                    "  [polling] this agent serves no conntrack event stream \
                     ({message}); polling every {interval}s instead, so a short \
                     flow can open and close between two reads and never appear."
                );
                return watch_conntrack_by_polling(client, interval).await;
            }
            Err(StreamOpenError::Failed(e)) => eprintln!("  [stream] {e}"),
        }

        eprintln!("  [stream] reconnecting in {}s", backoff.as_secs());
        tokio::time::sleep(backoff).await;
        backoff = next_backoff(backoff);
    }
}

/// What `conntrack watch` falls back to where the agent serves no event
/// stream, which is what a kernel built without `CONFIG_NF_CONNTRACK_PROCFS`
/// leaves: successive reads of the connection list, diffed.
async fn watch_conntrack_by_polling(client: &ApiClient, interval: u64) -> Result<()> {
    let mut prev_keys: std::collections::HashSet<String> = std::collections::HashSet::new();

    loop {
        let conns = client.list_connections(10_000).await?;
        let mut curr_keys = std::collections::HashSet::new();
        for c in &conns {
            let key = conntrack_key(c);
            if !prev_keys.contains(&key) {
                print_conntrack_line("new", &key, Some(&c.state));
            }
            curr_keys.insert(key);
        }
        for old_key in &prev_keys {
            if !curr_keys.contains(old_key) {
                print_conntrack_line("destroy", old_key, None);
            }
        }
        prev_keys = curr_keys;
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
    }
}

fn chrono_or_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => format!("{:.3}", d.as_secs_f64()),
        Err(_) => "0".to_string(),
    }
}

struct FlowAgg {
    flows: u64,
    bytes: u64,
    packets: u64,
}

/// Extract /24 subnet for IPv4 or /48 for IPv6.
fn subnet_of(ip: &str) -> String {
    if ip.contains(':') {
        // IPv6: keep first 3 groups (rough /48)
        let parts: Vec<&str> = ip.split(':').collect();
        if parts.len() >= 3 {
            format!("{}:{}:{}::/48", parts[0], parts[1], parts[2])
        } else {
            format!("{ip}/48")
        }
    } else {
        // IPv4: /24
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() == 4 {
            format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2])
        } else {
            ip.to_string()
        }
    }
}

// ── Risk Score ──────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
pub async fn cmd_score(client: &ApiClient, alert_limit: u64, output: OutputFormat) -> Result<()> {
    // Fetch all scoring inputs in parallel
    let (alerts_res, ddos_res, blacklist_res, iocs_res, conntrack_res) = tokio::join!(
        client.list_alerts(
            None,
            None,
            None,
            None,
            &crate::api_client::ANY_TRIAGE,
            alert_limit,
            0
        ),
        client.ddos_status(),
        client.list_ips_blacklist(),
        client.list_iocs(),
        client.conntrack_status(),
    );

    // ── Alert severity score (0-3) ──
    let mut alert_score: f64 = 0.0;
    let mut critical = 0u64;
    let mut high = 0u64;
    let mut medium = 0u64;
    let mut low = 0u64;
    if let Ok(ref resp) = alerts_res {
        for a in &resp.alerts {
            match a.severity.as_str() {
                "critical" => critical += 1,
                "high" => high += 1,
                "medium" => medium += 1,
                _ => low += 1,
            }
        }
        // Weighted: critical=4, high=2, medium=1, low=0.25
        #[allow(clippy::cast_precision_loss)]
        let weighted =
            (critical as f64 * 4.0) + (high as f64 * 2.0) + (medium as f64) + (low as f64 * 0.25);
        // Normalize: 0 alerts → 0, 50+ weighted → 3.0
        alert_score = (weighted / 50.0).min(1.0) * 3.0;
    }

    // ── DDoS score (0-2) ──
    let mut ddos_score: f64 = 0.0;
    let mut active_attacks = 0usize;
    let mut total_mitigated = 0u64;
    if let Ok(ref d) = ddos_res {
        active_attacks = d.active_attacks;
        total_mitigated = d.total_mitigated;
        if d.active_attacks > 0 {
            ddos_score = 2.0;
        } else if d.total_mitigated > 10 {
            ddos_score = 0.5;
        }
    }

    // ── Blacklist score (0-2) ──
    let blacklist_count = blacklist_res.as_ref().map_or(0, std::vec::Vec::len);
    let blacklist_score: f64 = match blacklist_count {
        0 => 0.0,
        1..=4 => 0.5,
        5..=19 => 1.0,
        _ => 2.0,
    };

    // ── Threat intel score (0-2) ──
    let ioc_count = iocs_res.as_ref().map_or(0, std::vec::Vec::len);
    let ti_score: f64 = match ioc_count {
        0 => 0.0,
        1..=9 => 0.5,
        10..=49 => 1.0,
        _ => 2.0,
    };

    // ── Connection anomaly score (0-1) ──
    let mut conn_score: f64 = 0.0;
    // A table nobody could read scores nothing rather than scoring clean.
    let conn_count = conntrack_res
        .as_ref()
        .ok()
        .and_then(|c| c.connection_count)
        .unwrap_or(0);
    // Very rough heuristic: >10k connections = suspicious
    if conn_count > 10_000 {
        conn_score = 1.0;
    } else if conn_count > 5_000 {
        conn_score = 0.5;
    }

    let total_score = alert_score + ddos_score + blacklist_score + ti_score + conn_score;
    // Clamp to 10.0
    let final_score = total_score.min(10.0);

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let label = match final_score as u32 {
        0..=2 => "Low",
        3..=5 => "Medium",
        6..=7 => "High",
        _ => "Critical",
    };

    if output == OutputFormat::Json {
        let json = serde_json::json!({
            "score": (final_score * 10.0).round() / 10.0,
            "label": label,
            "factors": {
                "alerts": (alert_score * 10.0).round() / 10.0,
                "ddos": ddos_score,
                "blacklist": blacklist_score,
                "threat_intel": ti_score,
                "connections": conn_score,
            },
            "details": {
                "alert_count": { "critical": critical, "high": high, "medium": medium, "low": low },
                "ddos_active": active_attacks,
                "ddos_mitigated": total_mitigated,
                "blacklisted_ips": blacklist_count,
                "ioc_matches": ioc_count,
                "active_connections": conn_count,
            }
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    println!();
    println!("  Network Risk Score: {final_score:.1} / 10 ({label})");
    println!();
    println!("  Contributing Factors:");
    println!(
        "    Alerts          {alert_score:.1}  ({critical} critical, {high} high, {medium} medium, {low} low)"
    );
    println!(
        "    DDoS            {ddos_score:.1}  ({active_attacks} active, {total_mitigated} mitigated total)"
    );
    println!("    Blacklist       {blacklist_score:.1}  ({blacklist_count} IPs blocked)");
    println!("    Threat Intel    {ti_score:.1}  ({ioc_count} IOC matches)");
    println!("    Connections     {conn_score:.1}  ({conn_count} active)");
    println!();

    Ok(())
}

// ── Identity ────────────────────────────────────────────────────────

pub async fn cmd_identity(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let identity = client.get_identity().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&identity)?);
        return Ok(());
    }

    let endpoint = identity.operator_endpoint.as_deref().unwrap_or("-");
    println!("Version:           {}", identity.version);
    println!("Hostname:          {}", identity.hostname);
    println!("Uptime (seconds):  {}", identity.uptime_seconds);
    println!(
        "Operator-managed:  {}",
        if identity.operator_managed {
            "yes"
        } else {
            "no"
        }
    );
    println!("Operator endpoint: {endpoint}");
    Ok(())
}

// ── Enhanced Status ─────────────────────────────────────────────────

pub async fn cmd_status_enhanced(client: &ApiClient, output: OutputFormat) -> Result<()> {
    // Fetch all data sources in parallel
    let (status, ebpf, alerts, conntrack, ddos) = tokio::join!(
        client.get_status(),
        client.ebpf_status(),
        client.list_alerts(None, None, None, None, &crate::api_client::ANY_TRIAGE, 5, 0),
        client.conntrack_status(),
        client.ddos_status(),
    );

    let status = status?;

    if output == OutputFormat::Json {
        let combined = serde_json::json!({
            "agent": status,
            "ebpf": ebpf.ok(),
            "alerts": alerts.ok(),
            "conntrack": conntrack.ok(),
            "ddos": ddos.ok(),
        });
        println!("{}", serde_json::to_string_pretty(&combined)?);
        return Ok(());
    }

    let uptime = format_uptime(status.uptime_seconds);

    println!(
        "eBPFsentinel v{} -- up {} -- {} rules loaded\n",
        status.version, uptime, status.rule_count
    );

    // eBPF programs
    if let Ok(ebpf) = ebpf {
        let loaded = ebpf.programs.iter().filter(|p| p.loaded).count();
        let total = ebpf.programs.len();
        print!("  Programs  {loaded}/{total} loaded   ");
        for p in &ebpf.programs {
            if p.loaded {
                print!(" {} \u{2713}", p.name);
            }
        }
        println!("\n");
    }

    // Connection tracking
    if let Ok(ct) = conntrack {
        match ct.connection_count {
            Some(count) => println!("  Conntrack  {count} active connections"),
            None => println!("  Conntrack  active connections unreadable"),
        }
    }

    // DDoS
    if let Ok(d) = ddos {
        if d.active_attacks > 0 {
            println!(
                "  DDoS       {} active attack(s), {} mitigated total",
                d.active_attacks, d.total_mitigated
            );
        } else {
            println!(
                "  DDoS       no active attacks ({} mitigated total)",
                d.total_mitigated
            );
        }
    }

    // Recent alerts
    if let Ok(al) = alerts {
        println!("\n  Recent Alerts ({} total)", al.total);
        if al.alerts.is_empty() {
            println!("  (none)");
        } else {
            let mut table = Table::new(&[
                ("COMPONENT", Align::Left),
                ("SEVERITY", Align::Left),
                ("SOURCE", Align::Left),
                ("DESTINATION", Align::Left),
                ("MESSAGE", Align::Left),
            ])
            .indent("  ");
            for a in &al.alerts {
                table.row(cells![
                    a.component,
                    a.severity,
                    a.src_ip_str(),
                    a.dst_ip_str(),
                    truncate(&a.message, 40)
                ]);
            }
            table.print();
        }
    }

    Ok(())
}

// ── Investigate ─────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
pub async fn cmd_investigate(
    client: &ApiClient,
    ip: &str,
    alert_limit: u64,
    output: OutputFormat,
) -> Result<()> {
    let target: std::net::IpAddr = ip
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid IP address: {ip}"))?;
    let target_str = target.to_string();

    // Fetch all data sources in parallel
    let (alerts_res, conns_res, dns_res, blacklist_res, iocs_res) = tokio::join!(
        client.list_alerts(
            None,
            None,
            None,
            None,
            &crate::api_client::ANY_TRIAGE,
            alert_limit,
            0
        ),
        client.list_connections(2000),
        client.dns_cache(None, Some(&target_str), 0, 50),
        client.list_ips_blacklist(),
        client.list_iocs(),
    );

    // Build target address as [u32; 4] for alert matching (IPv4 and IPv6)
    let target_addr: [u32; 4] = match target {
        std::net::IpAddr::V4(v4) => [u32::from(v4), 0, 0, 0],
        std::net::IpAddr::V6(v6) => {
            let octets = v6.octets();
            [
                u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]),
                u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]),
                u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]),
                u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]]),
            ]
        }
    };

    // Filter alerts where target is source or destination
    let matched_alerts: Vec<_> = alerts_res
        .as_ref()
        .ok()
        .map(|a| {
            a.alerts
                .iter()
                .filter(|a| {
                    a.src_addr.as_slice() == target_addr || a.dst_addr.as_slice() == target_addr
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // Filter connections by IP
    let conns = conns_res.ok().unwrap_or_default();
    let matched_conns: Vec<_> = conns
        .iter()
        .filter(|c| c.src_ip == target_str || c.dst_ip == target_str)
        .collect();

    // DNS reverse lookup
    let dns_entries = dns_res.ok();

    // Blacklist check
    let blacklist = blacklist_res.ok().unwrap_or_default();
    let bl_entry = blacklist.iter().find(|e| e.ip == target_str);

    // IOC matches
    let iocs = iocs_res.ok().unwrap_or_default();
    let matched_iocs: Vec<_> = iocs.iter().filter(|i| i.ip == target_str).collect();

    if output == OutputFormat::Json {
        let json = serde_json::json!({
            "ip": target_str,
            "blacklisted": bl_entry.is_some(),
            "blacklist_entry": bl_entry,
            "ioc_matches": matched_iocs,
            "alert_count": matched_alerts.len(),
            "alerts": matched_alerts,
            "connection_count": matched_conns.len(),
            "connections": matched_conns,
            "dns": dns_entries,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    // ── Header ──
    let bl_status = if let Some(entry) = bl_entry {
        format!(
            "YES ({}, {}s left)",
            truncate(&entry.reason, 48),
            entry.ttl_remaining_secs
        )
    } else {
        "no".to_string()
    };
    let ioc_status = if matched_iocs.is_empty() {
        "none".to_string()
    } else {
        format!("{} match(es)", matched_iocs.len())
    };

    println!();
    println!("  IP: {target_str}  |  Blacklisted: {bl_status}  |  IOC: {ioc_status}");
    println!();

    // ── Alerts ──
    println!("  Alerts: {} matching", matched_alerts.len());
    if !matched_alerts.is_empty() {
        let mut table = Table::new(&[
            ("COMPONENT", Align::Left),
            ("SEVERITY", Align::Left),
            ("ACTION", Align::Left),
            ("SOURCE", Align::Left),
            ("DESTINATION", Align::Left),
            ("MESSAGE", Align::Left),
        ])
        .indent("  ");
        for a in matched_alerts.iter().take(20) {
            table.row(cells![
                a.component,
                a.severity,
                a.action,
                a.src_ip_str(),
                a.dst_ip_str(),
                truncate(&a.message, 45)
            ]);
        }
        table.print();
        if matched_alerts.len() > 20 {
            println!("  ... and {} more", matched_alerts.len() - 20);
        }
    }
    println!();

    // ── Connections ──
    println!("  Connections: {} active", matched_conns.len());
    if !matched_conns.is_empty() {
        let mut table = Table::new(&[
            ("SOURCE", Align::Left),
            ("PORT", Align::Right),
            ("DESTINATION", Align::Left),
            ("PORT", Align::Right),
            ("PROTO", Align::Left),
            ("STATE", Align::Left),
            ("BYTES", Align::Right),
        ])
        .indent("  ");
        for c in matched_conns.iter().take(20) {
            let proto = match c.protocol {
                6 => "TCP",
                17 => "UDP",
                1 => "ICMP",
                _ => "?",
            };
            let total = u64::from(c.bytes_fwd) + u64::from(c.bytes_rev);
            table.row(cells![
                c.src_ip,
                c.src_port,
                c.dst_ip,
                c.dst_port,
                proto,
                c.state,
                format_bytes(total)
            ]);
        }
        table.print();
    }
    println!();

    // ── DNS ──
    if let Some(ref dns) = dns_entries
        && !dns.entries.is_empty()
    {
        println!("  DNS Reverse Lookups:");
        for e in &dns.entries {
            let blocked = if e.is_blocked { " [BLOCKED]" } else { "" };
            println!(
                "    {} -> {} (queries: {}){blocked}",
                e.domain,
                e.ips.join(", "),
                e.query_count,
            );
        }
        println!();
    }

    // ── IOCs ──
    if !matched_iocs.is_empty() {
        println!("  Threat Intel IOC Matches:");
        for ioc in &matched_iocs {
            println!(
                "    {} (type: {}, feed: {}, confidence: {})",
                ioc.ip, ioc.threat_type, ioc.source_feed, ioc.confidence,
            );
        }
        println!();
    }

    Ok(())
}

/// Format byte count to human-readable (K/M/G).
#[allow(clippy::cast_precision_loss)]
fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Cut free text to `max` characters, marking the cut. Counts characters
/// rather than bytes, so a message carrying an accent or a non-Latin name is
/// never sliced through the middle of one.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max.saturating_sub(3)).collect();
    format!("{kept}...")
}

fn yes_no(val: bool) -> &'static str {
    if val { "yes" } else { "no" }
}

/// How a rule's interface scope prints. A floating rule is every interface the
/// programs are attached to, so it prints as `*` rather than as a blank cell
/// that reads like a rule nothing applies to.
fn interface_scope(groups: &[String]) -> String {
    if groups.is_empty() {
        return "*".to_string();
    }
    groups.join(",")
}

fn format_uptime(seconds: u64) -> String {
    let h = seconds / 3600;
    let m = (seconds % 3600) / 60;
    let s = seconds % 60;
    if h > 0 {
        format!("{h}h {m:02}m {s:02}s")
    } else if m > 0 {
        format!("{m}m {s:02}s")
    } else {
        format!("{s}s")
    }
}

// ── NAT ─────────────────────────────────────────────────────────────

pub async fn cmd_nat_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.nat_status().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("NAT Status");
    println!("  Enabled:    {}", yes_no(status.enabled));
    println!("  Rule count: {}", status.rule_count);
    Ok(())
}

pub async fn cmd_nat_rules(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let rules = client.list_nat_rules().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&rules)?);
        return Ok(());
    }

    if rules.is_empty() {
        println!("No NAT rules configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("TYPE", Align::Left),
        ("DIR", Align::Left),
        ("PRIO", Align::Right),
        ("TRANSLATES TO", Align::Left),
        ("MATCHES", Align::Left),
        ("INTERFACES", Align::Left),
        ("ENABLED", Align::Left),
    ]);
    for r in &rules {
        table.row(cells![
            r.id,
            r.nat_type,
            r.direction,
            r.priority,
            r.translation.words(),
            nat_match_words(r),
            interface_scope(&r.interfaces),
            yes_no(r.enabled)
        ]);
    }
    table.print();
    Ok(())
}

/// What a NAT rule is narrowed to, written on one line.
///
/// A rule naming none of the criteria translates every packet its direction
/// carries, which is wider than any of the others rather than a blank cell.
fn nat_match_words(rule: &crate::api_client::NatRuleResponse) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(ref src) = rule.match_src {
        parts.push(format!("src {src}"));
    } else if let Some(ref alias) = rule.match_src_alias {
        parts.push(format!("src @{alias}"));
    }
    if let Some(ref dst) = rule.match_dst {
        parts.push(format!("dst {dst}"));
    } else if let Some(ref alias) = rule.match_dst_alias {
        parts.push(format!("dst @{alias}"));
    }
    if let Some(ref port) = rule.match_dst_port {
        parts.push(format!("port {port}"));
    }
    if let Some(ref proto) = rule.match_protocol {
        parts.push(proto.clone());
    }
    if parts.is_empty() {
        "any".to_string()
    } else {
        parts.join(" ")
    }
}

pub async fn cmd_nat_nptv6_list(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let rules = client.list_nptv6_rules().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&rules)?);
        return Ok(());
    }

    if rules.is_empty() {
        println!("No NPTv6 rules configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("INTERNAL", Align::Left),
        ("EXTERNAL", Align::Left),
        ("PREFIX", Align::Right),
        ("INTERFACES", Align::Left),
        ("ENABLED", Align::Left),
    ]);
    for r in &rules {
        table.row(cells![
            r.id,
            r.internal_prefix,
            r.external_prefix,
            format!("/{}", r.prefix_len),
            interface_scope(&r.interfaces),
            yes_no(r.enabled)
        ]);
    }
    table.print();
    Ok(())
}

pub async fn cmd_nat_nptv6_create(
    client: &ApiClient,
    id: &str,
    internal_prefix: &str,
    external_prefix: &str,
    prefix_len: u8,
    output: OutputFormat,
) -> Result<()> {
    let body = serde_json::json!({
        "id": id,
        "enabled": true,
        "internal_prefix": internal_prefix,
        "external_prefix": external_prefix,
        "prefix_len": prefix_len,
    });
    let rule = client.create_nptv6_rule(&body).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&rule)?);
        return Ok(());
    }

    println!(
        "NPTv6 rule created: {} ({} <-> {} /{})",
        rule.id, rule.internal_prefix, rule.external_prefix, rule.prefix_len
    );
    Ok(())
}

pub async fn cmd_nat_nptv6_delete(client: &ApiClient, id: &str) -> Result<()> {
    client.delete_nptv6_rule(id).await?;
    println!("NPTv6 rule deleted: {id}");
    Ok(())
}

// ── Zones ───────────────────────────────────────────────────────────────

pub async fn cmd_zones_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.zone_status().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("Zone Engine");
    println!("  Enabled:   {}", yes_no(status.enabled));
    println!("  Zones:     {}", status.zone_count);
    println!("  Policies:  {}", status.policy_count);
    Ok(())
}

pub async fn cmd_zones_list(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let zones = client.list_zones().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&zones)?);
        return Ok(());
    }

    if zones.is_empty() {
        println!("No zones configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("INTERFACES", Align::Left),
        ("DEFAULT", Align::Left),
    ]);

    for zone in &zones {
        table.row(cells![
            zone.id,
            zone.interfaces.join(","),
            zone.default_policy
        ]);
    }
    table.print();

    println!("\n{} zone(s) total.", zones.len());
    Ok(())
}

pub async fn cmd_zones_add(client: &ApiClient, json: &str, output: OutputFormat) -> Result<()> {
    let body: serde_json::Value =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;
    let zone = client.create_zone(&body).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&zone)?);
        return Ok(());
    }

    println!(
        "Zone created: {} (interfaces={}, default={})",
        zone.id,
        zone.interfaces.join(","),
        zone.default_policy
    );
    Ok(())
}

pub async fn cmd_zones_delete(client: &ApiClient, id: &str) -> Result<()> {
    client.delete_zone(id).await?;
    println!("Zone deleted: {id}");
    Ok(())
}

pub async fn cmd_zones_policies(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let policies = client.list_zone_policies().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&policies)?);
        return Ok(());
    }

    if policies.is_empty() {
        println!("No inter-zone policies configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("FROM", Align::Left),
        ("TO", Align::Left),
        ("POLICY", Align::Left),
        ("ACTION", Align::Left),
    ]);

    for policy in &policies {
        table.row(cells![
            policy.id,
            policy.from,
            policy.to,
            policy.policy,
            policy.action
        ]);
    }
    table.print();

    println!("\n{} policy(ies) total.", policies.len());
    Ok(())
}

pub async fn cmd_zones_add_policy(
    client: &ApiClient,
    json: &str,
    output: OutputFormat,
) -> Result<()> {
    let body: serde_json::Value =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;
    let policy = client.create_zone_policy(&body).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&policy)?);
        return Ok(());
    }

    println!(
        "Zone policy created: {} ({} -> {}, action={})",
        policy.id, policy.from, policy.to, policy.action
    );
    Ok(())
}

pub async fn cmd_zones_delete_policy(client: &ApiClient, id: &str) -> Result<()> {
    client.delete_zone_policy(id).await?;
    println!("Zone policy deleted: {id}");
    Ok(())
}

// ── Policy routing ──────────────────────────────────────────────────────

pub async fn cmd_routing_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.routing_status().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("Policy Routing");
    println!("  Enabled:   {}", yes_no(status.enabled));
    println!("  Gateways:  {}", status.gateway_count);
    Ok(())
}

pub async fn cmd_routing_gateways(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let gateways = client.list_gateways().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&gateways)?);
        return Ok(());
    }

    if gateways.is_empty() {
        println!("No gateways configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("NAME", Align::Left),
        ("INTERFACE", Align::Left),
        ("GATEWAY IP", Align::Left),
        ("PRI", Align::Right),
        ("WEIGHT", Align::Right),
        ("ENABLED", Align::Left),
        ("STATUS", Align::Left),
        ("HEALTH", Align::Left),
    ]);

    for gw in &gateways {
        table.row(cells![
            gw.id,
            gw.name,
            gw.interface,
            gw.gateway_ip,
            gw.priority,
            gw.weight,
            yes_no(gw.enabled),
            gw.status,
            gw.health_status
        ]);
    }
    table.print();

    println!("\n{} gateway(s) total.", gateways.len());
    Ok(())
}

pub async fn cmd_routing_add_gateway(
    client: &ApiClient,
    json: &str,
    output: OutputFormat,
) -> Result<()> {
    let body: serde_json::Value =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;
    let gw = client.create_gateway(&body).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&gw)?);
        return Ok(());
    }

    println!(
        "Gateway created: {} (interface={}, gateway={}, priority={})",
        gw.id, gw.interface, gw.gateway_ip, gw.priority
    );
    Ok(())
}

pub async fn cmd_routing_delete_gateway(client: &ApiClient, id: &str) -> Result<()> {
    client.delete_gateway(id).await?;
    println!("Gateway deleted: {id}");
    Ok(())
}

pub async fn cmd_routing_routes(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let routes = client.list_routes().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&routes)?);
        return Ok(());
    }

    if routes.is_empty() {
        println!("No routes configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("DESTINATION", Align::Left),
        ("GATEWAY ID", Align::Left),
        ("VIA", Align::Left),
    ]);

    for route in &routes {
        table.row(cells![
            route.destination,
            route.gateway_id,
            route.gateway_ip
        ]);
    }
    table.print();

    println!("\n{} route(s) total.", routes.len());
    Ok(())
}

// ── IDS ─────────────────────────────────────────────────────────────────

pub async fn cmd_ids_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.ids_status().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("Intrusion Detection");
    println!("  Enabled:  {}", yes_no(status.enabled));
    println!("  Mode:     {}", status.mode);
    println!("  Rules:    {}", status.rule_count);
    Ok(())
}

pub async fn cmd_ids_rules(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let rules = client.list_ids_rules().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&rules)?);
        return Ok(());
    }

    if rules.is_empty() {
        println!("No IDS rules configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("DESCRIPTION", Align::Left),
        ("SEVERITY", Align::Left),
        ("MODE", Align::Left),
        ("PROTO", Align::Left),
        ("MATCHES", Align::Left),
        ("INTERFACES", Align::Left),
        ("ENABLED", Align::Left),
        ("PATTERN", Align::Left),
    ]);

    for rule in &rules {
        table.row(cells![
            rule.id,
            rule.description,
            rule.severity,
            rule.mode,
            rule.protocol,
            ids_rule_match(rule),
            interface_scope(&rule.interfaces),
            yes_no(rule.enabled),
            rule.pattern
        ]);
    }
    table.print();

    println!("\n{} rule(s) total.", rules.len());
    print_ids_thresholds(&rules);
    print_ids_slot_conflicts(&rules);
    Ok(())
}

/// What a rule narrows on, so a rule watching a reply port or a resolved name
/// does not print as one matching every packet of its protocol.
fn ids_rule_match(rule: &IdsRuleResponse) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(port) = rule.dst_port {
        parts.push(format!("dst {port}"));
    }
    if let Some(port) = rule.src_port {
        parts.push(format!("src {port}"));
    }
    if let Some(ref domain) = rule.domain_pattern {
        let mode = rule.domain_match_mode.as_deref().unwrap_or("exact");
        parts.push(format!("{domain} ({mode})"));
    }
    if parts.is_empty() {
        return "-".to_string();
    }
    parts.join(" ")
}

/// A rate-based rule alerts on a count over a window rather than on every
/// match, and a per-country override makes it stricter for some traffic than
/// the table above can say.
fn print_ids_thresholds(rules: &[IdsRuleResponse]) {
    let rated: Vec<&IdsRuleResponse> = rules
        .iter()
        .filter(|r| r.threshold.is_some() || r.country_thresholds.is_some())
        .collect();
    if rated.is_empty() {
        return;
    }
    println!("\nRate thresholds:");
    for rule in rated {
        if let Some(ref t) = rule.threshold {
            println!(
                "  {}: {} {} per {}s tracked by {}",
                rule.id, t.threshold_type, t.count, t.window_secs, t.track_by,
            );
        }
        let Some(ref by_country) = rule.country_thresholds else {
            continue;
        };
        for (code, t) in by_country {
            println!(
                "  {} [{}]: {} {} per {}s tracked by {}",
                rule.id, code, t.threshold_type, t.count, t.window_secs, t.track_by,
            );
        }
    }
}

/// A detection rule that lost its kernel slot still prints as enabled above,
/// which is exactly the reading an operator must not walk away with.
fn print_ids_slot_conflicts(rules: &[IdsRuleResponse]) {
    let shadowed: Vec<&IdsRuleResponse> =
        rules.iter().filter(|r| r.kernel_slot.is_some()).collect();
    if shadowed.is_empty() {
        return;
    }
    println!("\nKernel map slot conflicts:");
    for rule in shadowed {
        let Some(ref slot) = rule.kernel_slot else {
            continue;
        };
        let fate = if slot.evaluated_in_userspace {
            "still evaluated in userspace"
        } else {
            "DETECTS NOTHING"
        };
        println!(
            "  {} loses its slot to {} - {}",
            rule.id,
            slot.shadowed_by.join(", "),
            fate,
        );
    }
}

// ── GeoIP ───────────────────────────────────────────────────────────────

pub async fn cmd_geoip_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.geoip_status().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("GeoIP");
    println!("  Enabled:  {}", yes_no(status.enabled));
    println!("  Ready:    {}", yes_no(status.ready));
    Ok(())
}

pub async fn cmd_geoip_lookup(client: &ApiClient, ip: &str, output: OutputFormat) -> Result<()> {
    let resp = client.geoip_lookup(ip).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    let asn = resp.asn.map_or_else(|| "-".to_string(), |a| a.to_string());
    println!("GeoIP lookup: {}", resp.ip);
    println!(
        "  Country:  {} ({})",
        resp.country_name.as_deref().unwrap_or("-"),
        resp.country_code.as_deref().unwrap_or("-")
    );
    println!("  City:     {}", resp.city.as_deref().unwrap_or("-"));
    println!("  ASN:      {asn}");
    println!("  AS org:   {}", resp.as_org.as_deref().unwrap_or("-"));
    Ok(())
}

// ── eBPF ────────────────────────────────────────────────────────────────

pub async fn cmd_ebpf_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.ebpf_status().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    if status.programs.is_empty() {
        println!("No eBPF programs reported.");
    } else {
        let mut table = Table::new(&[("PROGRAM", Align::Left), ("LOADED", Align::Left)]);
        for prog in &status.programs {
            table.row(cells![prog.name, yes_no(prog.loaded)]);
        }
        table.print();
        println!("\n{} program(s) reported.", status.programs.len());
    }

    if status.attach_blocked.is_empty() {
        return Ok(());
    }

    println!("\nAttaches refused by the kernel:");
    let mut table = Table::new(&[
        ("PROGRAM", Align::Left),
        ("INTERFACE", Align::Left),
        ("NESTED XDP", Align::Left),
        ("REASON", Align::Left),
    ]);
    for block in &status.attach_blocked {
        table.row(cells![
            block.program,
            block.interface,
            yes_no(block.nested_xdp),
            block.reason
        ]);
    }
    table.print();
    Ok(())
}

pub async fn cmd_ebpf_uprobes(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.list_uprobes().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("Uprobe inventory: {} library(ies)", resp.libraries);

    if resp.probes.is_empty() {
        println!("No uprobes attached.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("LIB", Align::Left),
        ("PATH", Align::Left),
        ("PROGRAM", Align::Left),
        ("SYMBOL", Align::Left),
        ("OFFSET", Align::Left),
        ("RETPROBE", Align::Left),
        ("BROKERED", Align::Left),
        ("STICKY", Align::Left),
    ]);

    for probe in &resp.probes {
        table.row(cells![
            probe.lib,
            probe.path,
            probe.program,
            probe.symbol,
            probe.offset,
            yes_no(probe.retprobe),
            yes_no(probe.brokered),
            yes_no(probe.sticky)
        ]);
    }
    table.print();

    println!("\n{} probe(s) attached.", resp.probes.len());
    Ok(())
}

pub async fn cmd_ebpf_kernel_features(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.kernel_features().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("Kernel feature probe");
    println!("  Probed:     {}", yes_no(resp.probed));
    println!("  Load mode:  {}", resp.load_mode);
    if let Some(reason) = &resp.reason {
        println!("  Reason:     {reason}");
    }

    if !resp.program_types.is_empty() {
        println!();
        let mut table = Table::new(&[("PROGRAM TYPE", Align::Left), ("SUPPORTED", Align::Left)]);
        for pt in &resp.program_types {
            table.row(cells![pt.program_type, yes_no(pt.supported)]);
        }
        table.print();
    }

    if !resp.helpers.is_empty() {
        println!();
        let mut table = Table::new(&[
            ("PROGRAM TYPE", Align::Left),
            ("HELPER", Align::Left),
            ("SUPPORTED", Align::Left),
        ]);
        for helper in &resp.helpers {
            table.row(cells![
                helper.program_type,
                helper.helper,
                yes_no(helper.supported)
            ]);
        }
        table.print();
    }

    if resp.missing_required.is_empty() {
        println!("\nNo required helper is missing.");
    } else {
        println!("\nRequired helpers the kernel does not provide:");
        let mut table = Table::new(&[
            ("OBJECT", Align::Left),
            ("PROGRAM TYPE", Align::Left),
            ("HELPER", Align::Left),
            ("DETAIL", Align::Left),
        ]);
        for missing in &resp.missing_required {
            table.row(cells![
                missing.object,
                missing.program_type,
                missing.helper,
                missing.detail
            ]);
        }
        table.print();
    }
    Ok(())
}

// ── Config ──────────────────────────────────────────────────────────────

pub async fn cmd_config_show(client: &ApiClient) -> Result<()> {
    let config = client.get_config().await?;
    println!("{}", serde_json::to_string_pretty(&config)?);
    Ok(())
}

/// Write one section of the configuration file and reload.
///
/// The document is read from `path`, or from standard input where none is
/// named, so a section can be piped straight back out of an editor. It is
/// rooted at the section's own key, exactly the way `config show` renders
/// it.
pub async fn cmd_config_set(
    client: &ApiClient,
    section: &str,
    path: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let yaml = if let Some(path) = path {
        std::fs::read_to_string(path)
            .with_context(|| format!("configuration section unreadable at {path}"))?
    } else {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .context("configuration section unreadable on standard input")?;
        buf
    };

    let resp = client.put_config_section(section, &yaml).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("Section {section} written.");
    println!("Reload {}: {}", resp.status, resp.message);
    Ok(())
}

pub async fn cmd_config_reload(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.reload_config().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("Reload {}: {}", resp.status, resp.message);
    Ok(())
}

// ── DLP ─────────────────────────────────────────────────────────────────

pub async fn cmd_dlp_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.dlp_status().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("Data Loss Prevention");
    println!("  Enabled:   {}", yes_no(status.enabled));
    println!("  Mode:      {}", status.mode);
    println!("  Patterns:  {}", status.pattern_count);
    Ok(())
}

pub async fn cmd_dlp_patterns(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let patterns = client.list_dlp_patterns().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&patterns)?);
        return Ok(());
    }

    if patterns.is_empty() {
        println!("No DLP patterns configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("NAME", Align::Left),
        ("SEVERITY", Align::Left),
        ("DATA TYPE", Align::Left),
        ("MODE", Align::Left),
        ("ENABLED", Align::Left),
        ("REGEX", Align::Left),
    ]);

    for pattern in &patterns {
        table.row(cells![
            pattern.id,
            pattern.name,
            pattern.severity,
            pattern.data_type,
            pattern.mode,
            yes_no(pattern.enabled),
            pattern.regex
        ]);
    }
    table.print();

    println!("\n{} pattern(s) total.", patterns.len());
    Ok(())
}

// ── TLS ─────────────────────────────────────────────────────────────────

pub async fn cmd_tls_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.tls_status().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("API listener TLS");
    println!("  TLS:              {}", yes_no(status.tls));
    println!(
        "  Negotiated group: {}",
        status.negotiated_group.as_deref().unwrap_or("-")
    );
    println!("  Post-quantum:     {}", yes_no(status.post_quantum));
    Ok(())
}

// ── Aliases ─────────────────────────────────────────────────────────────

pub async fn cmd_aliases_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.alias_status().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("Alias Engine");
    println!("  Aliases:  {}", status.alias_count);
    Ok(())
}

pub async fn cmd_aliases_set_content(
    client: &ApiClient,
    id: &str,
    json: &str,
    output: OutputFormat,
) -> Result<()> {
    let body: serde_json::Value =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("invalid JSON: {e}"))?;
    let resp = client.set_alias_content(id, &body).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("Alias content replaced: {id}");
    Ok(())
}

// ── Threat intelligence: URLs and refresh ───────────────────────────────

pub async fn cmd_threatintel_urls(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let urls = client.list_url_iocs().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&urls)?);
        return Ok(());
    }

    if urls.is_empty() {
        println!("No URL indicators loaded.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("URL", Align::Left),
        ("FEED", Align::Left),
        ("CONF", Align::Right),
        ("THREAT TYPE", Align::Left),
    ]);

    for url in &urls {
        table.row(cells![
            url.url,
            url.feed_id,
            url.confidence,
            url.threat_type
        ]);
    }
    table.print();

    println!("\n{} URL indicator(s) total.", urls.len());
    Ok(())
}

pub async fn cmd_threatintel_feeds_refresh(
    client: &ApiClient,
    feed_id: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let resp = client.refresh_feeds(feed_id).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("Refresh {}: {}", resp.status, resp.message);
    Ok(())
}

// ── IPS blacklist mutation ──────────────────────────────────────────────

pub async fn cmd_ips_blacklist_add(
    client: &ApiClient,
    ip: &str,
    reason: Option<&str>,
    ttl_secs: Option<u64>,
    output: OutputFormat,
) -> Result<()> {
    let resp = client.add_blacklist_entry(ip, reason, ttl_secs).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!(
        "Blacklisted {} ({}), TTL {}s",
        resp.ip, resp.reason, resp.ttl_remaining_secs
    );
    Ok(())
}

pub async fn cmd_ips_blacklist_delete(
    client: &ApiClient,
    ip: &str,
    output: OutputFormat,
) -> Result<()> {
    let resp = client.remove_blacklist_entry(ip).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("Removed from blacklist: {}", resp.ip);
    Ok(())
}

// ── JA4S ────────────────────────────────────────────────────────────────

pub async fn cmd_fingerprints_ja4s(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.ja4s_summary().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("JA4S Fingerprint Cache");
    println!("  Cached entries:  {}", resp.cached_count);
    println!("  Max size:        {}", resp.max_size);
    println!("  TTL:             {}s", resp.ttl_seconds);
    println!("  Persistent:      {}", yes_no(resp.persistent));
    Ok(())
}

// ── DNS status and conntrack flush ──────────────────────────────────────

pub async fn cmd_dns_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.dns_status().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("DNS Interception");
    println!("  Enabled:            {}", yes_no(status.enabled));
    println!("  Blocklist patterns: {}", status.blocklist_pattern_count);
    println!("  Domains blocked:    {}", status.blocklist_domains_blocked);
    println!("  IPs injected:       {}", status.blocklist_ips_injected);
    Ok(())
}

pub async fn cmd_conntrack_flush(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.conntrack_flush().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("Conntrack table flushed: {} entry(ies).", resp.flushed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_uptime_seconds_only() {
        assert_eq!(format_uptime(42), "42s");
    }

    #[test]
    fn format_uptime_minutes_and_seconds() {
        assert_eq!(format_uptime(125), "2m 05s");
    }

    #[test]
    fn format_uptime_hours() {
        assert_eq!(format_uptime(3723), "1h 02m 03s");
    }

    #[test]
    fn format_uptime_zero() {
        assert_eq!(format_uptime(0), "0s");
    }

    #[test]
    fn truncate_leaves_short_text_whole() {
        assert_eq!(truncate("port scan", 10), "port scan");
    }

    /// A cut counts characters, so text carrying a multi-byte character is
    /// never sliced through one, which a byte index would panic on.
    #[test]
    fn truncate_cuts_on_characters_not_bytes() {
        assert_eq!(truncate("éééééééééé", 6), "ééé...");
    }

    #[test]
    fn yes_no_true() {
        assert_eq!(yes_no(true), "yes");
    }

    #[test]
    fn yes_no_false() {
        assert_eq!(yes_no(false), "no");
    }

    #[test]
    fn interface_scope_names_every_group_a_rule_was_declared_in() {
        assert_eq!(
            interface_scope(&["dmz".to_string(), "wan".to_string()]),
            "dmz,wan"
        );
        assert_eq!(interface_scope(&["!wan".to_string()]), "!wan");
    }

    /// A rule in no group is on every interface, so an empty cell would read
    /// as the opposite of what the agent enforces.
    #[test]
    fn interface_scope_reads_a_floating_rule_as_every_interface() {
        assert_eq!(interface_scope(&[]), "*");
    }

    fn an_ips_rule() -> IpsRuleResponse {
        IpsRuleResponse {
            id: "ips-001".to_string(),
            description: "Reverse shell callback".to_string(),
            severity: "critical".to_string(),
            mode: "block".to_string(),
            protocol: "tcp".to_string(),
            dst_port: Some(4444),
            pattern: "/bin/sh".to_string(),
            enabled: true,
            domain_pattern: None,
            domain_match_mode: None,
            kernel_slot: None,
            interfaces: Vec::new(),
        }
    }

    #[test]
    fn ips_rule_match_names_the_port_a_rule_is_pinned_to() {
        assert_eq!(ips_rule_match(&an_ips_rule()), "dst 4444");
    }

    /// A rule decided on a resolved name carries no payload pattern, so the
    /// port alone would read as a rule watching everything on it.
    #[test]
    fn ips_rule_match_names_the_resolved_name_a_rule_is_decided_on() {
        let rule = IpsRuleResponse {
            dst_port: Some(443),
            pattern: String::new(),
            domain_pattern: Some("*.c2-hosting.example".to_string()),
            domain_match_mode: Some("wildcard".to_string()),
            ..an_ips_rule()
        };
        assert_eq!(
            ips_rule_match(&rule),
            "dst 443 *.c2-hosting.example (wildcard)"
        );
    }

    /// A rule narrowed by nothing but its protocol reads as a dash rather
    /// than as a blank cell.
    #[test]
    fn ips_rule_match_says_a_rule_narrows_on_nothing() {
        let rule = IpsRuleResponse {
            dst_port: None,
            ..an_ips_rule()
        };
        assert_eq!(ips_rule_match(&rule), "-");
    }

    #[test]
    fn conntrack_event_type_display() {
        use domain::conntrack::entity::ConntrackEventType;
        assert_eq!(ConntrackEventType::New.as_str(), "new");
        assert_eq!(ConntrackEventType::Update.as_str(), "update");
        assert_eq!(ConntrackEventType::Destroy.as_str(), "destroy");
    }
}

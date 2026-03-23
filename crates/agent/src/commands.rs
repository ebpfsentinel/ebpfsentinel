use std::net::Ipv4Addr;

use anyhow::Result;

use crate::api_client::ApiClient;
use crate::cli::OutputFormat;

// ── Health ──────────────────────────────────────────────────────────────

pub async fn cmd_health(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let health = client.healthz().await?;
    let ready = client.readyz().await?;

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

    println!(
        "{:<16} {:>4}  {:<6}  {:<5}  {:<18}  {:<18}  {:>8}  {:>8}  {:<12}  {:<7}",
        "ID",
        "PRI",
        "ACTION",
        "PROTO",
        "SRC IP",
        "DST IP",
        "SRC PORT",
        "DST PORT",
        "SCOPE",
        "ENABLED"
    );

    for rule in &rules {
        println!(
            "{:<16} {:>4}  {:<6}  {:<5}  {:<18}  {:<18}  {:>8}  {:>8}  {:<12}  {:<7}",
            rule.id,
            rule.priority,
            rule.action,
            rule.protocol,
            rule.src_ip.as_deref().unwrap_or("-"),
            rule.dst_ip.as_deref().unwrap_or("-"),
            rule.src_port.as_deref().unwrap_or("-"),
            rule.dst_port.as_deref().unwrap_or("-"),
            rule.scope,
            yes_no(rule.enabled),
        );
    }

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

    println!(
        "{:<16} {:>4}  {:<6}  {:<18}  {:<18}  {:>8}  {:<7}",
        "ID", "PRI", "ACTION", "SRC IP", "DST IP", "DST PORT", "ENABLED"
    );

    for rule in &rules {
        println!(
            "{:<16} {:>4}  {:<6}  {:<18}  {:<18}  {:>8}  {:<7}",
            rule.id,
            rule.priority,
            rule.action,
            rule.src_ip.as_deref().unwrap_or("-"),
            rule.dst_ip.as_deref().unwrap_or("-"),
            rule.dst_port.as_deref().unwrap_or("-"),
            yes_no(rule.enabled),
        );
    }

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

    println!(
        "{:<16}  {:<8}  {:<7}  {:<5}  {:>8}  {:<30}  {:<7}",
        "ID", "SEVERITY", "MODE", "PROTO", "DST PORT", "PATTERN", "ENABLED"
    );

    for rule in &rules {
        let dst_port = rule
            .dst_port
            .map_or_else(|| "-".to_string(), |p| p.to_string());
        println!(
            "{:<16}  {:<8}  {:<7}  {:<5}  {:>8}  {:<30}  {:<7}",
            rule.id,
            rule.severity,
            rule.mode,
            rule.protocol,
            dst_port,
            rule.pattern,
            yes_no(rule.enabled),
        );
    }

    println!("\n{} rule(s) total.", rules.len());
    Ok(())
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

    println!(
        "{:<18}  {:<30}  {:<6}  {:>8}",
        "IP", "REASON", "AUTO", "TTL (s)"
    );

    for entry in &entries {
        println!(
            "{:<18}  {:<30}  {:<6}  {:>8}",
            entry.ip,
            entry.reason,
            yes_no(entry.auto_generated),
            entry.ttl_remaining_secs,
        );
    }

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

    println!(
        "{:<18}  {:<25}  {:<15}  {:>8}",
        "IP", "DOMAIN", "SOURCE", "TTL (s)"
    );

    for entry in &entries {
        println!(
            "{:<18}  {:<25}  {:<15}  {:>8}",
            entry.ip, entry.domain, entry.source, entry.ttl_remaining_secs,
        );
    }

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

    println!(
        "{:<16}  {:<12}  {:>8}  {:>8}  {:<6}  {:<16}  {:<18}  {:<7}",
        "ID", "SCOPE", "RATE", "BURST", "ACTION", "ALGORITHM", "SRC IP", "ENABLED"
    );

    for rule in &rules {
        println!(
            "{:<16}  {:<12}  {:>8}  {:>8}  {:<6}  {:<16}  {:<18}  {:<7}",
            rule.id,
            rule.scope,
            rule.rate,
            rule.burst,
            rule.action,
            rule.algorithm,
            rule.src_ip.as_deref().unwrap_or("-"),
            yes_no(rule.enabled),
        );
    }

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
        "Rate limit rule created: {} (rate={}, burst={}, scope={})",
        rule.id, rule.rate, rule.burst, rule.scope
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

    println!(
        "{:<18}  {:<20}  {:>4}  {:<12}  {:<20}",
        "IP", "FEED ID", "CONF", "THREAT TYPE", "SOURCE FEED"
    );

    for ioc in &iocs {
        println!(
            "{:<18}  {:<20}  {:>4}  {:<12}  {:<20}",
            ioc.ip, ioc.feed_id, ioc.confidence, ioc.threat_type, ioc.source_feed,
        );
    }

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

    println!(
        "{:<16}  {:<20}  {:<8}  {:<7}  {:>12}  {:>8}  {:>4}",
        "ID", "NAME", "FORMAT", "ENABLED", "REFRESH (s)", "MAX IOCs", "CONF"
    );

    for feed in &feeds {
        println!(
            "{:<16}  {:<20}  {:<8}  {:<7}  {:>12}  {:>8}  {:>4}",
            feed.id,
            feed.name,
            feed.format,
            yes_no(feed.enabled),
            feed.refresh_interval_secs,
            feed.max_iocs,
            feed.min_confidence,
        );
    }

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
    limit: u64,
    offset: u64,
    output: OutputFormat,
) -> Result<()> {
    let resp = client
        .list_alerts(component, severity, tactic, technique, limit, offset)
        .await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    if resp.alerts.is_empty() {
        println!("No alerts found.");
        return Ok(());
    }

    println!(
        "{:<16}  {:<10}  {:<8}  {:<10}  {:<6}  {:<18}  {:<18}  {:>5}  {:>5}  {:<3}  {:<20}  {:<20}  {:<30}",
        "ID",
        "COMPONENT",
        "SEVERITY",
        "RULE ID",
        "ACTION",
        "SRC IP",
        "DST IP",
        "SPORT",
        "DPORT",
        "FP",
        "SRC DOMAIN",
        "DST DOMAIN",
        "MESSAGE"
    );

    for alert in &resp.alerts {
        let msg = if alert.message.len() > 30 {
            format!("{}...", &alert.message[..27])
        } else {
            alert.message.clone()
        };
        let src_domain = alert.src_domain.as_deref().unwrap_or("-");
        let dst_domain = alert.dst_domain.as_deref().unwrap_or("-");
        println!(
            "{:<16}  {:<10}  {:<8}  {:<10}  {:<6}  {:<18}  {:<18}  {:>5}  {:>5}  {:<3}  {:<20}  {:<20}  {:<30}",
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
            truncate(src_domain, 20),
            truncate(dst_domain, 20),
            msg,
        );
    }

    println!(
        "\nShowing {}/{} alert(s) (offset={}).",
        resp.alerts.len(),
        resp.total,
        resp.offset
    );
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

    let resp = client.list_alerts(None, None, None, None, limit, 0).await?;
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
        "  Alerts: {} total ({} critical, {} high, {} medium, {} low)",
        total, critical, high, medium, low
    );
    println!();

    // Top sources
    let mut src_sorted: Vec<_> = by_src.iter().collect();
    src_sorted.sort_by(|a, b| b.1.cmp(a.1));
    println!("  Top Sources              Alerts");
    println!("  {}", "-".repeat(40));
    for (ip, count) in src_sorted.iter().take(10) {
        println!("  {:<24} {:>6}", truncate(ip, 24), count);
    }
    println!();

    // Top rules
    let mut rule_sorted: Vec<_> = by_rule.iter().collect();
    rule_sorted.sort_by(|a, b| (b.1).1.cmp(&(a.1).1));
    println!("  Top Rules                Alerts  Severity");
    println!("  {}", "-".repeat(50));
    for (rule, (severity, count)) in rule_sorted.iter().take(10) {
        println!("  {:<24} {:>6}  {}", truncate(rule, 24), count, severity);
    }
    println!();

    // Component distribution
    let mut comp_sorted: Vec<_> = by_component.iter().collect();
    comp_sorted.sort_by(|a, b| b.1.cmp(a.1));
    let max_count = comp_sorted.first().map(|&(_, &c)| c).unwrap_or(1);
    println!("  Components               Alerts");
    println!("  {}", "-".repeat(50));
    for &(comp, &count) in &comp_sorted {
        let bar_len = ((count as f64 / max_count as f64) * 20.0) as usize;
        let bar: String = "\u{2588}".repeat(bar_len);
        println!("  {:<12} {:>6}  {}", comp, count, bar);
    }
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

    println!(
        "{:<12}  {:<12}  {:<55}  {:<22}  DESCRIPTION",
        "COMPONENT", "TECHNIQUE", "NAME", "TACTIC"
    );

    for t in &resp.techniques {
        println!(
            "{:<12}  {:<12}  {:<55}  {:<22}  {}",
            t.component, t.technique_id, t.technique_name, t.tactic, t.description,
        );
    }

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
    println!(
        "{:<20}  {:<8}  {:<30}  {:>8}  {:>10}  OUTPUT",
        "ID", "STATUS", "FILTER", "DURATION", "SIZE"
    );
    for c in &resp.captures {
        println!(
            "{:<20}  {:<8}  {:<30}  {:>7}s  {:>9}B  {}",
            c.id,
            c.status,
            truncate(&c.filter, 30),
            c.duration_secs,
            c.file_size_bytes,
            c.output_path,
        );
    }
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
    println!(
        "{:<20}  {:<12}  {:<18}  {:>8}  {:>10}  {:<7}",
        "ID", "ACTION", "TARGET", "TTL", "REMAINING", "REVOKED"
    );
    for a in &resp.actions {
        println!(
            "{:<20}  {:<12}  {:<18}  {:>7}s  {:>9}s  {:<7}",
            a.id, a.action_type, a.target, a.ttl_secs, a.remaining_secs, a.revoked,
        );
    }
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

    println!(
        "{:<12}  {:<14}  {:<18}  {:<18}  {:>5}  {:>5}  {:<10}  {:<30}",
        "COMPONENT", "ACTION", "SRC IP", "DST IP", "SPORT", "DPORT", "RULE ID", "DETAIL"
    );

    for entry in &resp.entries {
        let detail = if entry.detail.len() > 30 {
            format!("{}...", &entry.detail[..27])
        } else {
            entry.detail.clone()
        };
        println!(
            "{:<12}  {:<14}  {:<18}  {:<18}  {:>5}  {:>5}  {:<10}  {:<30}",
            entry.component,
            entry.action,
            format_ip(entry.src_ip),
            format_ip(entry.dst_ip),
            entry.src_port,
            entry.dst_port,
            entry.rule_id,
            detail,
        );
    }

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
    println!(
        "{:>4}  {:<14}  {:<12}  {:<8}  {:<40}",
        "VER", "ACTION", "COMPONENT", "ACTOR", "AFTER"
    );

    for entry in &resp.entries {
        let after = entry.after.as_deref().unwrap_or("-");
        let after_display = if after.len() > 40 {
            format!("{}...", &after[..37])
        } else {
            after.to_string()
        };
        println!(
            "{:>4}  {:<14}  {:<12}  {:<8}  {:<40}",
            entry.version, entry.action, entry.component, entry.actor, after_display,
        );
    }

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

    println!(
        "{:<30}  {:<30}  {:>8}  {:>8}  {:<7}",
        "DOMAIN", "IPs", "TTL (s)", "QUERIES", "BLOCKED"
    );

    for entry in &resp.entries {
        let ips = entry.ips.join(", ");
        let ips_display = if ips.len() > 30 {
            format!("{}...", &ips[..27])
        } else {
            ips
        };
        println!(
            "{:<30}  {:<30}  {:>8}  {:>8}  {:<7}",
            truncate(&entry.domain, 30),
            ips_display,
            entry.ttl_remaining_secs,
            entry.query_count,
            yes_no(entry.is_blocked),
        );
    }

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
        println!("  {:<30}  {:>8}", "DOMAIN", "QUERIES");
        for entry in &stats.top_queried {
            println!(
                "  {:<30}  {:>8}",
                truncate(&entry.domain, 30),
                entry.query_count
            );
        }
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

    println!("{:<30}  {:<8}  {:>8}", "PATTERN", "ACTION", "MATCHES");

    for rule in &rules {
        println!(
            "{:<30}  {:<8}  {:>8}",
            truncate(&rule.pattern, 30),
            rule.action,
            rule.match_count,
        );
    }

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

    println!(
        "{:<30}  {:>6}  {:<30}  {:<7}",
        "DOMAIN", "SCORE", "FACTORS", "BLOCKED"
    );

    for entry in &resp.entries {
        let factors = if entry.factors.is_empty() {
            "-".to_string()
        } else {
            entry.factors.join(", ")
        };
        println!(
            "{:<30}  {:>6.3}  {:<30}  {:<7}",
            truncate(&entry.domain, 30),
            entry.score,
            truncate(&factors, 30),
            yes_no(entry.is_blocked),
        );
    }

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

    println!(
        "{:<16}  {:<18}  {:<10}  {:>10}  {:>10}  {:>12}  {:>8}",
        "ID", "ATTACK TYPE", "STATUS", "PEAK PPS", "CUR PPS", "TOTAL PKTS", "SOURCES"
    );

    for a in &attacks {
        println!(
            "{:<16}  {:<18}  {:<10}  {:>10}  {:>10}  {:>12}  {:>8}",
            a.id,
            a.attack_type,
            a.status,
            a.peak_pps,
            a.current_pps,
            a.total_packets,
            a.source_count,
        );
    }

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

    println!(
        "{:<16}  {:<18}  {:<10}  {:>10}  {:>10}  {:>12}  {:>8}",
        "ID", "ATTACK TYPE", "STATUS", "PEAK PPS", "CUR PPS", "TOTAL PKTS", "SOURCES"
    );

    for a in &attacks {
        println!(
            "{:<16}  {:<18}  {:<10}  {:>10}  {:>10}  {:>12}  {:>8}",
            a.id,
            a.attack_type,
            a.status,
            a.peak_pps,
            a.current_pps,
            a.total_packets,
            a.source_count,
        );
    }

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

    println!(
        "{:<16}  {:<18}  {:>12}  {:<10}  {:>12}  {:<7}",
        "ID", "ATTACK TYPE", "THRESH PPS", "ACTION", "BLOCK (s)", "ENABLED"
    );

    for p in &policies {
        println!(
            "{:<16}  {:<18}  {:>12}  {:<10}  {:>12}  {:<7}",
            p.id,
            p.attack_type,
            p.detection_threshold_pps,
            p.mitigation_action,
            p.auto_block_duration_secs,
            yes_no(p.enabled),
        );
    }

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

    println!(
        "{:<16}  {:<20}  {:<8}  {:>6}  {:<14}  {:>8}  {:<7}",
        "ID", "NAME", "PROTO", "PORT", "ALGORITHM", "BACKENDS", "ENABLED"
    );

    for svc in &services {
        println!(
            "{:<16}  {:<20}  {:<8}  {:>6}  {:<14}  {:>8}  {:<7}",
            svc.id,
            truncate(&svc.name, 20),
            svc.protocol,
            svc.listen_port,
            svc.algorithm,
            svc.backend_count,
            yes_no(svc.enabled),
        );
    }

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
    println!("  Enabled:   {}", yes_no(svc.enabled));

    if svc.backends.is_empty() {
        println!("\n  No backends.");
    } else {
        println!(
            "\n  {:<12}  {:<18}  {:>6}  {:>6}  {:<9}  {:>6}  {:<7}",
            "BACKEND", "ADDR", "PORT", "WEIGHT", "STATUS", "CONNS", "ENABLED"
        );
        for be in &svc.backends {
            println!(
                "  {:<12}  {:<18}  {:>6}  {:>6}  {:<9}  {:>6}  {:<7}",
                be.id,
                be.addr,
                be.port,
                be.weight,
                be.status,
                be.active_connections,
                yes_no(be.enabled),
            );
        }
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

// ── QoS ─────────────────────────────────────────────────────────────

pub async fn cmd_qos_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.qos_status().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("QoS / Traffic Shaping Status");
    println!("  Enabled:          {}", yes_no(status.enabled));
    println!("  Scheduler:        {}", status.scheduler);
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

    println!(
        "{:<16}  {:>14}  {:>14}",
        "ID", "RATE (bps)", "BURST (bytes)"
    );

    for pipe in &pipes {
        println!(
            "{:<16}  {:>14}  {:>14}",
            pipe.id, pipe.rate_bps, pipe.burst_bytes,
        );
    }

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

    println!("{:<16}  {:<16}  {:>6}", "ID", "PIPE ID", "WEIGHT");

    for queue in &queues {
        println!(
            "{:<16}  {:<16}  {:>6}",
            queue.id, queue.pipe_id, queue.weight,
        );
    }

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

    println!(
        "{:<16}  {:<16}  {:<8}  {:>4}",
        "ID", "QUEUE ID", "DIR", "PRI"
    );

    for cls in &classifiers {
        println!(
            "{:<16}  {:<16}  {:<8}  {:>4}",
            cls.id, cls.queue_id, cls.direction, cls.priority,
        );
    }

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

    println!(
        "QoS queue created: {} (pipe={}, weight={})",
        queue.id, queue.pipe_id, queue.weight
    );
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
        "QoS classifier created: {} (queue={}, direction={}, priority={})",
        cls.id, cls.queue_id, cls.direction, cls.priority
    );
    Ok(())
}

pub async fn cmd_qos_delete_classifier(client: &ApiClient, id: &str) -> Result<()> {
    client.delete_qos_classifier(id).await?;
    println!("QoS classifier deleted: {id}");
    Ok(())
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
            let ta = (a.packets_fwd as u64) + (a.packets_rev as u64);
            let tb = (b.packets_fwd as u64) + (b.packets_rev as u64);
            tb.cmp(&ta)
        }),
        _ => conns.sort_by(|a, b| {
            let ta = (a.bytes_fwd as u64) + (a.bytes_rev as u64);
            let tb = (b.bytes_fwd as u64) + (b.bytes_rev as u64);
            tb.cmp(&ta)
        }),
    }

    conns.truncate(limit);

    if conns.is_empty() {
        println!("No active connections.");
        return Ok(());
    }

    println!(
        "{:<22} {:>5}  {:<22} {:>5}  {:<5}  {:<6}  {:>10}  {:>10}",
        "SOURCE", "PORT", "DESTINATION", "PORT", "PROTO", "STATE", "BYTES", "PACKETS"
    );
    println!("{}", "-".repeat(100));

    for c in &conns {
        let total_bytes = (c.bytes_fwd as u64) + (c.bytes_rev as u64);
        let total_pkts = (c.packets_fwd as u64) + (c.packets_rev as u64);
        let proto = match c.protocol {
            6 => "TCP",
            17 => "UDP",
            1 => "ICMP",
            58 => "ICMPv6",
            _ => "OTHER",
        };
        println!(
            "{:<22} {:>5}  {:<22} {:>5}  {:<5}  {:<6}  {:>10}  {:>10}",
            truncate(&c.src_ip, 22),
            c.src_port,
            truncate(&c.dst_ip, 22),
            c.dst_port,
            proto,
            truncate(&c.state, 6),
            format_bytes(total_bytes),
            total_pkts,
        );
    }

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
        entry.bytes += (c.bytes_fwd as u64) + (c.bytes_rev as u64);
        entry.packets += (c.packets_fwd as u64) + (c.packets_rev as u64);
    }

    let mut sorted: Vec<(String, FlowAgg)> = agg.into_iter().collect();
    sorted.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes));

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

    println!(
        "{:<60} {:>6}  {:>10}  {:>10}",
        "FLOW", "CONNS", "BYTES", "PACKETS"
    );
    println!("{}", "-".repeat(92));

    for (key, agg) in &sorted {
        println!(
            "{:<60} {:>6}  {:>10}  {:>10}",
            truncate(key, 60),
            agg.flows,
            format_bytes(agg.bytes),
            agg.packets,
        );
    }

    println!(
        "\n{} aggregated flow(s) from {} connection(s).",
        sorted.len(),
        conns.len()
    );
    Ok(())
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

pub async fn cmd_score(client: &ApiClient, alert_limit: u64, output: OutputFormat) -> Result<()> {
    // Fetch all scoring inputs in parallel
    let (alerts_res, ddos_res, blacklist_res, iocs_res, conntrack_res) = tokio::join!(
        client.list_alerts(None, None, None, None, alert_limit, 0),
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
    let mut blacklist_score: f64 = 0.0;
    let blacklist_count = blacklist_res.as_ref().map(|b| b.len()).unwrap_or(0);
    // 1+ blocked IP = 0.5, 5+ = 1.0, 20+ = 2.0
    blacklist_score = match blacklist_count {
        0 => 0.0,
        1..=4 => 0.5,
        5..=19 => 1.0,
        _ => 2.0,
    };

    // ── Threat intel score (0-2) ──
    let mut ti_score: f64 = 0.0;
    let ioc_count = iocs_res.as_ref().map(|i| i.len()).unwrap_or(0);
    // IOC matches: 1+ = 0.5, 10+ = 1.0, 50+ = 2.0
    ti_score = match ioc_count {
        0 => 0.0,
        1..=9 => 0.5,
        10..=49 => 1.0,
        _ => 2.0,
    };

    // ── Connection anomaly score (0-1) ──
    let mut conn_score: f64 = 0.0;
    let conn_count = conntrack_res
        .as_ref()
        .map(|c| c.connection_count)
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
    println!("  Network Risk Score: {:.1} / 10 ({})", final_score, label);
    println!();
    println!("  Contributing Factors:");
    println!(
        "    Alerts          {:.1}  ({} critical, {} high, {} medium, {} low)",
        alert_score, critical, high, medium, low
    );
    println!(
        "    DDoS            {:.1}  ({} active, {} mitigated total)",
        ddos_score, active_attacks, total_mitigated
    );
    println!(
        "    Blacklist       {:.1}  ({} IPs blocked)",
        blacklist_score, blacklist_count
    );
    println!(
        "    Threat Intel    {:.1}  ({} IOC matches)",
        ti_score, ioc_count
    );
    println!(
        "    Connections     {:.1}  ({} active)",
        conn_score, conn_count
    );
    println!();

    Ok(())
}

// ── Enhanced Status ─────────────────────────────────────────────────

pub async fn cmd_status_enhanced(client: &ApiClient, output: OutputFormat) -> Result<()> {
    // Fetch all data sources in parallel
    let (status, ebpf, alerts, conntrack, ddos) = tokio::join!(
        client.get_status(),
        client.ebpf_status(),
        client.list_alerts(None, None, None, None, 5, 0),
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
        println!("  Conntrack  {} active connections", ct.connection_count);
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
            println!(
                "  {:<10}  {:<8}  {:<18}  {:<18}  {}",
                "COMPONENT", "SEVERITY", "SOURCE", "DESTINATION", "MESSAGE"
            );
            for a in &al.alerts {
                println!(
                    "  {:<10}  {:<8}  {:<18}  {:<18}  {}",
                    a.component,
                    a.severity,
                    a.src_ip_str(),
                    a.dst_ip_str(),
                    truncate(&a.message, 40),
                );
            }
        }
    }

    Ok(())
}

// ── Investigate ─────────────────────────────────────────────────────

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
        client.list_alerts(None, None, None, None, alert_limit, 0),
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
            truncate(&entry.reason, 30),
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
    println!(
        "  IP: {}  |  Blacklisted: {}  |  IOC: {}",
        target_str, bl_status, ioc_status
    );
    println!();

    // ── Alerts ──
    println!("  Alerts: {} matching", matched_alerts.len());
    if !matched_alerts.is_empty() {
        println!(
            "  {:<10}  {:<8}  {:<6}  {:<18}  {:<18}  {}",
            "COMPONENT", "SEVERITY", "ACTION", "SOURCE", "DESTINATION", "MESSAGE"
        );
        for a in matched_alerts.iter().take(20) {
            println!(
                "  {:<10}  {:<8}  {:<6}  {:<18}  {:<18}  {}",
                a.component,
                a.severity,
                a.action,
                a.src_ip_str(),
                a.dst_ip_str(),
                truncate(&a.message, 45),
            );
        }
        if matched_alerts.len() > 20 {
            println!("  ... and {} more", matched_alerts.len() - 20);
        }
    }
    println!();

    // ── Connections ──
    println!("  Connections: {} active", matched_conns.len());
    if !matched_conns.is_empty() {
        println!(
            "  {:<22} {:>5}  {:<22} {:>5}  {:<5}  {:<6}  {:>10}",
            "SOURCE", "PORT", "DESTINATION", "PORT", "PROTO", "STATE", "BYTES"
        );
        for c in matched_conns.iter().take(20) {
            let proto = match c.protocol {
                6 => "TCP",
                17 => "UDP",
                1 => "ICMP",
                _ => "?",
            };
            let total = (c.bytes_fwd as u64) + (c.bytes_rev as u64);
            println!(
                "  {:<22} {:>5}  {:<22} {:>5}  {:<5}  {:<6}  {:>10}",
                truncate(&c.src_ip, 22),
                c.src_port,
                truncate(&c.dst_ip, 22),
                c.dst_port,
                proto,
                truncate(&c.state, 6),
                format_bytes(total),
            );
        }
    }
    println!();

    // ── DNS ──
    if let Some(ref dns) = dns_entries {
        if !dns.entries.is_empty() {
            println!("  DNS Reverse Lookups:");
            for e in &dns.entries {
                let blocked = if e.is_blocked { " [BLOCKED]" } else { "" };
                println!(
                    "    {} -> {} (queries: {}){}",
                    e.domain,
                    e.ips.join(", "),
                    e.query_count,
                    blocked
                );
            }
            println!();
        }
    }

    // ── IOCs ──
    if !matched_iocs.is_empty() {
        println!("  Threat Intel IOC Matches:");
        for ioc in &matched_iocs {
            println!(
                "    {} (type: {}, feed: {}, confidence: {})",
                ioc.ip,
                ioc.threat_type,
                truncate(&ioc.source_feed, 20),
                ioc.confidence,
            );
        }
        println!();
    }

    Ok(())
}

/// Format byte count to human-readable (K/M/G).
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

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max.saturating_sub(3)])
    } else {
        s.to_string()
    }
}

fn yes_no(val: bool) -> &'static str {
    if val { "yes" } else { "no" }
}

fn format_ip(raw: u32) -> String {
    if raw == 0 {
        "-".to_string()
    } else {
        Ipv4Addr::from(raw).to_string()
    }
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

    println!(
        "{:<20}  {:<12}  {:<8}  {:>8}  {:<7}",
        "ID", "TYPE", "DIR", "PRIORITY", "ENABLED"
    );
    for r in &rules {
        println!(
            "{:<20}  {:<12}  {:<8}  {:>8}  {:<7}",
            r.id,
            r.nat_type,
            r.direction,
            r.priority,
            yes_no(r.enabled)
        );
    }
    Ok(())
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

    println!(
        "{:<20}  {:<24}  {:<24}  {:>6}  {:<7}",
        "ID", "INTERNAL", "EXTERNAL", "PREFIX", "ENABLED"
    );
    for r in &rules {
        println!(
            "{:<20}  {:<24}  {:<24}  {:>6}  {:<7}",
            r.id,
            r.internal_prefix,
            r.external_prefix,
            format!("/{}", r.prefix_len),
            yes_no(r.enabled)
        );
    }
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
    fn yes_no_true() {
        assert_eq!(yes_no(true), "yes");
    }

    #[test]
    fn yes_no_false() {
        assert_eq!(yes_no(false), "no");
    }

    #[test]
    fn format_ip_zero_is_dash() {
        assert_eq!(format_ip(0), "-");
    }

    #[test]
    fn format_ip_localhost() {
        assert_eq!(format_ip(0x7F00_0001), "127.0.0.1");
    }

    #[test]
    fn format_ip_private() {
        assert_eq!(format_ip(0xC0A8_0101), "192.168.1.1");
    }
}

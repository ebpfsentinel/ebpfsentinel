use std::net::Ipv4Addr;

use anyhow::Result;

use crate::api_client::{
    AlertResponse, ApiClient, ConnectionResponse, ConntrackEventFrame, IpsRuleResponse,
    StreamOpenError,
};
use crate::cli::OutputFormat;

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
        "{:<16}  {:<18}  {:>8}  {:>8}  {:<6}  {:<16}  {:<7}",
        "ID", "SRC IP", "RATE", "BURST", "ACTION", "ALGORITHM", "ENABLED"
    );

    for rule in &rules {
        println!(
            "{:<16}  {:<18}  {:>8}  {:>8}  {:<6}  {:<16}  {:<7}",
            rule.id,
            rule.src_ip,
            rule.rate,
            rule.burst,
            rule.action,
            rule.algorithm,
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
        "  Alerts: {total} total ({critical} critical, {high} high, {medium} medium, {low} low)"
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
    rule_sorted.sort_by_key(|item| std::cmp::Reverse((item.1).1));
    println!("  Top Rules                Alerts  Severity");
    println!("  {}", "-".repeat(50));
    for (rule, (severity, count)) in rule_sorted.iter().take(10) {
        println!("  {:<24} {:>6}  {}", truncate(rule, 24), count, severity);
    }
    println!();

    // Component distribution
    let mut comp_sorted: Vec<_> = by_component.iter().collect();
    comp_sorted.sort_by(|a, b| b.1.cmp(a.1));
    let max_count = comp_sorted.first().map_or(1, |&(_, &c)| c);
    println!("  Components               Alerts");
    println!("  {}", "-".repeat(50));
    for &(comp, &count) in &comp_sorted {
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let bar_len = ((count as f64 / max_count as f64) * 20.0) as usize;
        let bar: String = "\u{2588}".repeat(bar_len);
        println!("  {comp:<12} {count:>6}  {bar}");
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

    println!(
        "\n  {:<20}  {:<18}  {:>12}  {:<10}",
        "NAME", "ADDR", "ARP_REPLIES", "ANNOUNCED"
    );
    for vip in &status.vips {
        println!(
            "  {:<20}  {:<18}  {:>12}  {:<10}",
            truncate(&vip.name, 20),
            vip.addr,
            vip.arp_replies,
            yes_no(vip.self_announced),
        );
    }
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

    println!(
        "{:<16}  {:>14}  {:>14}  {:<8}  {:>9}  {:>7}  {:<8}",
        "ID", "RATE (bps)", "BURST (bytes)", "DIR", "DELAY(ms)", "LOSS(%)", "STATE"
    );

    for pipe in &pipes {
        println!(
            "{:<16}  {:>14}  {:>14}  {:<8}  {:>9}  {:>7.2}  {:<8}",
            pipe.id,
            pipe.rate_bps,
            pipe.burst_bytes,
            pipe.direction,
            pipe.delay_ms,
            pipe.loss_pct,
            if pipe.enabled { "enabled" } else { "disabled" },
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

    println!("{:<16}  {:<16}  {:<8}", "ID", "PIPE ID", "STATE");

    for queue in &queues {
        println!(
            "{:<16}  {:<16}  {:<8}",
            queue.id,
            queue.pipe_id,
            if queue.enabled { "enabled" } else { "disabled" }
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

    println!("{:<16}  {:<16}  {:>4}", "ID", "QUEUE ID", "PRI");

    for cls in &classifiers {
        println!("{:<16}  {:<16}  {:>4}", cls.id, cls.queue_id, cls.priority);
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
        "  {:<10}  {}  {:<18} -> {:<18}  {}",
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
        .list_alerts(component, severity, None, None, 100, 0)
        .await
    {
        for a in &resp.alerts {
            seen.insert(a.id.clone());
        }
    }

    loop {
        tokio::time::sleep(interval).await;

        let resp = match client
            .list_alerts(component, severity, None, None, 50, 0)
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

    println!(
        "{:<22} {:>5}  {:<22} {:>5}  {:<5}  {:<6}  {:>10}  {:>10}",
        "SOURCE", "PORT", "DESTINATION", "PORT", "PROTO", "STATE", "BYTES", "PACKETS"
    );
    println!("{}", "-".repeat(100));

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

// ── Conntrack ──────────────────────────────────────────────────────────

pub async fn cmd_conntrack_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.conntrack_status().await?;
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        println!(
            "enabled: {}\nconnections: {} / {}",
            resp.enabled, resp.connection_count, resp.max_connections
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
        println!(
            "{:<16} {:<16} {:>6} {:>6} {:>5} {:>12} {:>12} {:>12}",
            "SRC", "DST", "SPORT", "DPORT", "PROTO", "STATE", "PKT_FWD", "PKT_REV"
        );
        for c in &conns {
            println!(
                "{:<16} {:<16} {:>6} {:>6} {:>5} {:>12} {:>12} {:>12}",
                c.src_ip,
                c.dst_ip,
                c.src_port,
                c.dst_port,
                c.protocol,
                c.state,
                c.packets_fwd,
                c.packets_rev,
            );
        }
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
    let conn_count = conntrack_res.as_ref().map_or(0, |c| c.connection_count);
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
                "  {:<10}  {:<8}  {:<18}  {:<18}  MESSAGE",
                "COMPONENT", "SEVERITY", "SOURCE", "DESTINATION"
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
    println!("  IP: {target_str}  |  Blacklisted: {bl_status}  |  IOC: {ioc_status}");
    println!();

    // ── Alerts ──
    println!("  Alerts: {} matching", matched_alerts.len());
    if !matched_alerts.is_empty() {
        println!(
            "  {:<10}  {:<8}  {:<6}  {:<18}  {:<18}  MESSAGE",
            "COMPONENT", "SEVERITY", "ACTION", "SOURCE", "DESTINATION"
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
            let total = u64::from(c.bytes_fwd) + u64::from(c.bytes_rev);
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

    println!("{:<16}  {:<40}  {:<14}", "ID", "INTERFACES", "DEFAULT");

    for zone in &zones {
        println!(
            "{:<16}  {:<40}  {:<14}",
            zone.id,
            zone.interfaces.join(","),
            zone.default_policy,
        );
    }

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

    println!(
        "{:<24}  {:<12}  {:<12}  {:<10}  {:<8}",
        "ID", "FROM", "TO", "POLICY", "ACTION"
    );

    for policy in &policies {
        println!(
            "{:<24}  {:<12}  {:<12}  {:<10}  {:<8}",
            policy.id, policy.from, policy.to, policy.policy, policy.action,
        );
    }

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

    println!(
        "{:<16}  {:<16}  {:<10}  {:<18}  {:>4}  {:>6}  {:<7}  {:<10}  {:<10}",
        "ID", "NAME", "INTERFACE", "GATEWAY IP", "PRI", "WEIGHT", "ENABLED", "STATUS", "HEALTH"
    );

    for gw in &gateways {
        println!(
            "{:<16}  {:<16}  {:<10}  {:<18}  {:>4}  {:>6}  {:<7}  {:<10}  {:<10}",
            gw.id,
            gw.name,
            gw.interface,
            gw.gateway_ip,
            gw.priority,
            gw.weight,
            yes_no(gw.enabled),
            gw.status,
            gw.health_status,
        );
    }

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

    println!("{:<24}  {:<16}  {:<18}", "DESTINATION", "GATEWAY ID", "VIA");

    for route in &routes {
        println!(
            "{:<24}  {:<16}  {:<18}",
            route.destination, route.gateway_id, route.gateway_ip,
        );
    }

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

    println!(
        "{:<16}  {:<30}  {:<8}  {:<6}  {:<6}  {:>8}  {:<7}  {:<20}",
        "ID", "DESCRIPTION", "SEVERITY", "MODE", "PROTO", "DST PORT", "ENABLED", "PATTERN"
    );

    for rule in &rules {
        let dst_port = rule
            .dst_port
            .map_or_else(|| "-".to_string(), |p| p.to_string());
        println!(
            "{:<16}  {:<30}  {:<8}  {:<6}  {:<6}  {:>8}  {:<7}  {:<20}",
            rule.id,
            rule.description,
            rule.severity,
            rule.mode,
            rule.protocol,
            dst_port,
            yes_no(rule.enabled),
            rule.pattern,
        );
    }

    println!("\n{} rule(s) total.", rules.len());
    Ok(())
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
        println!("{:<28}  {:<7}", "PROGRAM", "LOADED");
        for prog in &status.programs {
            println!("{:<28}  {:<7}", prog.name, yes_no(prog.loaded));
        }
        println!("\n{} program(s) reported.", status.programs.len());
    }

    if status.attach_blocked.is_empty() {
        return Ok(());
    }

    println!("\nAttaches refused by the kernel:");
    println!(
        "{:<28}  {:<12}  {:<11}  REASON",
        "PROGRAM", "INTERFACE", "NESTED XDP"
    );
    for block in &status.attach_blocked {
        println!(
            "{:<28}  {:<12}  {:<11}  {}",
            block.program,
            block.interface,
            yes_no(block.nested_xdp),
            block.reason,
        );
    }
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

    println!(
        "{:<10}  {:<40}  {:<20}  {:<16}  {:<8}  {:<8}  {:<8}  {:<6}",
        "LIB", "PATH", "PROGRAM", "SYMBOL", "OFFSET", "RETPROBE", "BROKERED", "STICKY"
    );

    for probe in &resp.probes {
        println!(
            "{:<10}  {:<40}  {:<20}  {:<16}  {:<8}  {:<8}  {:<8}  {:<6}",
            probe.lib,
            probe.path,
            probe.program,
            probe.symbol,
            probe.offset,
            yes_no(probe.retprobe),
            yes_no(probe.brokered),
            yes_no(probe.sticky),
        );
    }

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
        println!("\n{:<24}  {:<9}", "PROGRAM TYPE", "SUPPORTED");
        for pt in &resp.program_types {
            println!("{:<24}  {:<9}", pt.program_type, yes_no(pt.supported));
        }
    }

    if !resp.helpers.is_empty() {
        println!(
            "\n{:<24}  {:<32}  {:<9}",
            "PROGRAM TYPE", "HELPER", "SUPPORTED"
        );
        for helper in &resp.helpers {
            println!(
                "{:<24}  {:<32}  {:<9}",
                helper.program_type,
                helper.helper,
                yes_no(helper.supported),
            );
        }
    }

    if resp.missing_required.is_empty() {
        println!("\nNo required helper is missing.");
    } else {
        println!("\nRequired helpers the kernel does not provide:");
        println!(
            "{:<24}  {:<24}  {:<32}  DETAIL",
            "OBJECT", "PROGRAM TYPE", "HELPER"
        );
        for missing in &resp.missing_required {
            println!(
                "{:<24}  {:<24}  {:<32}  {}",
                missing.object, missing.program_type, missing.helper, missing.detail,
            );
        }
    }
    Ok(())
}

// ── Config ──────────────────────────────────────────────────────────────

pub async fn cmd_config_show(client: &ApiClient) -> Result<()> {
    let config = client.get_config().await?;
    println!("{}", serde_json::to_string_pretty(&config)?);
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

    println!(
        "{:<16}  {:<20}  {:<8}  {:<14}  {:<7}  {:<30}",
        "ID", "NAME", "SEVERITY", "DATA TYPE", "ENABLED", "REGEX"
    );

    for pattern in &patterns {
        println!(
            "{:<16}  {:<20}  {:<8}  {:<14}  {:<7}  {:<30}",
            pattern.id,
            pattern.name,
            pattern.severity,
            pattern.data_type,
            yes_no(pattern.enabled),
            pattern.regex,
        );
    }

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

    println!(
        "{:<60}  {:<16}  {:>4}  {:<16}",
        "URL", "FEED", "CONF", "THREAT TYPE"
    );

    for url in &urls {
        println!(
            "{:<60}  {:<16}  {:>4}  {:<16}",
            url.url, url.feed_id, url.confidence, url.threat_type,
        );
    }

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
    fn yes_no_true() {
        assert_eq!(yes_no(true), "yes");
    }

    #[test]
    fn yes_no_false() {
        assert_eq!(yes_no(false), "no");
    }

    #[test]
    fn conntrack_event_type_display() {
        use domain::conntrack::entity::ConntrackEventType;
        assert_eq!(ConntrackEventType::New.as_str(), "new");
        assert_eq!(ConntrackEventType::Update.as_str(), "update");
        assert_eq!(ConntrackEventType::Destroy.as_str(), "destroy");
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

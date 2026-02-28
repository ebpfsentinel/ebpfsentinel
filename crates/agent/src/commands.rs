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

// ── Agent Status ────────────────────────────────────────────────────────

pub async fn cmd_status(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.get_status().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    let uptime = format_uptime(status.uptime_seconds);
    let ebpf = if status.ebpf_loaded { "yes" } else { "no" };

    println!("eBPFsentinel Agent Status");
    println!("  Version:      {}", status.version);
    println!("  Uptime:       {uptime}");
    println!("  eBPF loaded:  {ebpf}");
    println!("  Rule count:   {}", status.rule_count);
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
    limit: u64,
    offset: u64,
    output: OutputFormat,
) -> Result<()> {
    let resp = client
        .list_alerts(component, severity, limit, offset)
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
            format_ip(alert.src_ip),
            format_ip(alert.dst_ip),
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

// ── Audit ───────────────────────────────────────────────────────────────

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
        // 127.0.0.1 = 0x7F000001 = 2130706433
        assert_eq!(format_ip(0x7F00_0001), "127.0.0.1");
    }

    #[test]
    fn format_ip_private() {
        // 192.168.1.1 = 0xC0A80101
        assert_eq!(format_ip(0xC0A8_0101), "192.168.1.1");
    }
}

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::api_client::{
    AlertResponse, ApiClient, ConnectionResponse, ConntrackEventFrame, IdsRuleResponse,
    IpsRuleResponse, LearningScopeBody, LearningSelector, LearningSessionResponse,
    NetpolReplayBody, NetpolReplayResponse, StartLearningBody, StreamOpenError,
    SuricataKeywordCount, SuricataRefusalResponse, SuricataReportResponse, SuricataRulesetResponse,
    TraceBody, TraceResponse,
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
        ("MODE", Align::Left),
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
            rule.mode,
            yes_no(rule.enabled)
        ]);
    }
    table.print();

    println!("\n{} rule(s) total.", rules.len());
    Ok(())
}

/// `firewall workload` - the workload rules in force, with their refusals.
pub async fn cmd_firewall_workload(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let listing = client.workload_rules().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&listing)?);
        return Ok(());
    }

    if listing.rules.is_empty() {
        println!("No workload rule is in force.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("RULE", Align::Left),
        ("VERDICT", Align::Left),
        ("MODE", Align::Left),
        ("SELECTOR", Align::Left),
        ("DESTINATION", Align::Left),
        ("DENIALS", Align::Right),
    ]);
    for rule in &listing.rules {
        table.row(cells![
            rule.rule,
            if rule.allows { "allow" } else { "deny" },
            rule.mode,
            rule.selector,
            rule.destination,
            rule.denials
        ]);
    }
    table.print();
    print_source_only(&listing.rules);

    if !listing.enforcing {
        println!("\nNo rule in force refuses: every one of them only counts.");
    }
    Ok(())
}

/// `firewall shadow` - what each shadow rule would have done.
pub async fn cmd_firewall_shadow(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let report = client.firewall_shadow().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    if report.rules.is_empty() {
        println!("No rule is in shadow mode.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("RULE", Align::Left),
        ("WOULD", Align::Left),
        ("INSTALLED", Align::Left),
        ("PACKETS", Align::Right),
        ("FLOWS", Align::Right),
        ("CHANGED PKTS", Align::Right),
        ("CHANGED FLOWS", Align::Right),
    ]);
    for rule in &report.rules {
        table.row(cells![
            rule.rule_id,
            rule.would,
            yes_no(rule.installed),
            rule.packets,
            rule.flows,
            rule.changed_packets,
            rule.changed_flows
        ]);
    }
    table.print();

    for rule in report.rules.iter().filter(|r| !r.sample.is_empty()) {
        println!("\n{} - most recent flows:", rule.rule_id);
        for flow in &rule.sample {
            println!(
                "  {}:{} -> {}:{} proto {} live {} ({} packets)",
                flow.src_ip,
                flow.src_port,
                flow.dst_ip,
                flow.dst_port,
                flow.protocol,
                flow.live_verdict,
                flow.packets
            );
        }
    }
    println!(
        "\nCounters restart whenever the set of shadow rules changes. Flow counts are a floor."
    );
    Ok(())
}

/// `firewall fqdn` - what each rule naming a destination by name has
/// resolved, and what is still open.
///
/// A pattern under which nothing ever resolved is printed as such rather
/// than left out: on a rule that allows, it is usually a typo.
pub async fn cmd_firewall_fqdn(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let listing = client.workload_fqdn().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&listing)?);
        return Ok(());
    }

    if listing.rules.is_empty() {
        println!("No workload rule names a destination by name.");
        return Ok(());
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let mut table = Table::new(&[
        ("RULE", Align::Left),
        ("PATTERN", Align::Left),
        ("NAME", Align::Left),
        ("ADDRESSES", Align::Right),
        ("WORKLOADS", Align::Right),
        ("REFRESHED", Align::Left),
        ("EXPIRES IN", Align::Left),
    ]);
    let mut never = 0usize;
    for rule in &listing.rules {
        for pattern in &rule.patterns {
            if pattern.names.is_empty() {
                never += 1;
                table.row(cells![
                    rule.rule,
                    pattern.pattern,
                    "never resolved",
                    0,
                    0,
                    "-",
                    "-"
                ]);
            }
            for name in &pattern.names {
                table.row(cells![
                    rule.rule,
                    pattern.pattern,
                    name.name,
                    name.addresses,
                    name.workloads,
                    format!(
                        "{} ago",
                        format_uptime(now.saturating_sub(name.refreshed_at))
                    ),
                    name.expires_at.map_or_else(
                        || "lapsed".to_string(),
                        |at| format_uptime(at.saturating_sub(now))
                    )
                ]);
            }
        }
    }
    table.print();

    if never > 0 {
        println!(
            "\n{never} pattern(s) never resolved since the policy was published: check the spelling and that the workload asks a listed resolver."
        );
    }
    Ok(())
}

/// `firewall labels` - the containers whose labels carry policy.
///
/// A container whose labels were refused is printed with the reason, since
/// none of its rules is in force and a silent omission would read as a
/// container nobody labelled.
pub async fn cmd_firewall_labels(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let listing = client.workload_labels().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&listing)?);
        return Ok(());
    }

    if listing.containers.is_empty() {
        println!("No container carries a policy label.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("CONTAINER", Align::Left),
        ("NAME", Align::Left),
        ("MODE", Align::Left),
        ("RULES", Align::Right),
        ("REFUSED", Align::Left),
    ]);
    for container in &listing.containers {
        let refused = container
            .problems
            .iter()
            .map(|problem| format!("{}: {}", problem.label, problem.reason))
            .collect::<Vec<_>>()
            .join("; ");
        table.row(cells![
            container.container_id.chars().take(12).collect::<String>(),
            container.container_name,
            container.mode,
            container.rules.len(),
            if refused.is_empty() {
                "-".to_string()
            } else {
                refused
            }
        ]);
    }
    table.print();
    Ok(())
}

/// `firewall reach` - what the workload rules let a workload reach.
///
/// The first support question on a deny-by-default policy is why an
/// application cannot connect, and the answer is almost never the rule the
/// person wrote: it is the one above it. So the whole list comes back in the
/// order the kernel walks it rather than the rule that would decide.
pub async fn cmd_firewall_reach(
    client: &ApiClient,
    pid: Option<u32>,
    exe: Option<String>,
    unit: Option<String>,
    container_id: Option<String>,
    container_name: Option<String>,
    output: OutputFormat,
) -> Result<()> {
    let mut query: Vec<(&str, String)> = Vec::new();
    if let Some(pid) = pid {
        query.push(("pid", pid.to_string()));
    }
    for (name, value) in [
        ("exe", exe),
        ("unit", unit),
        ("container_id", container_id),
        ("container_name", container_name),
    ] {
        if let Some(value) = value {
            query.push((name, value));
        }
    }
    if query.is_empty() {
        bail!("name the workload with --pid, --exe, --unit, --container-id or --container-name");
    }

    let reach = client.workload_reach(&query).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&reach)?);
        return Ok(());
    }

    println!("Workload:");
    for (label, value) in [
        ("executable", reach.exe.as_deref()),
        ("unit", reach.unit.as_deref()),
        ("cgroup", reach.cgroup.as_deref()),
        ("container id", reach.container_id.as_deref()),
        ("container name", reach.container_name.as_deref()),
    ] {
        if let Some(value) = value {
            println!("  {label}: {value}");
        }
    }

    if reach.rules.is_empty() {
        println!("\nNo workload rule names this workload.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("RULE", Align::Left),
        ("VERDICT", Align::Left),
        ("MODE", Align::Left),
        ("SELECTOR", Align::Left),
        ("DESTINATION", Align::Left),
        ("DENIALS", Align::Right),
    ]);
    for rule in &reach.rules {
        table.row(cells![
            rule.rule,
            if rule.allows { "allow" } else { "deny" },
            rule.mode,
            rule.selector,
            rule.destination,
            rule.denials
        ]);
    }
    table.print();
    print_source_only(&reach.rules);

    println!(
        "\n{} rule(s) name this workload, in the order the kernel walks them. The first one \
         admitting a destination decides.",
        reach.rules.len()
    );
    if !reach.enforcing {
        println!("No rule in force refuses: every one of them only counts.");
    }
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
    if let Some(workload) = alert.workload.as_ref() {
        println!("  Workload:       {}", workload.summary());
        if let Some(ancestry) = workload.ancestry.as_ref() {
            println!("  Started by:     {}", ancestry.chain());
        }
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

    if !resp.switched_off.is_empty() {
        let mut components: Vec<&str> = resp
            .switched_off
            .iter()
            .map(|t| t.component.as_str())
            .collect();
        components.sort_unstable();
        components.dedup();
        println!(
            "\nMapped but switched off: {} technique(s)  [{}]",
            resp.switched_off.len(),
            components.join(", "),
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

// ── Processes ───────────────────────────────────────────────────────

pub async fn cmd_processes_list(
    client: &ApiClient,
    limit: usize,
    output: OutputFormat,
) -> Result<()> {
    let resp = client.list_processes().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("Process table");
    println!("  Tracepoints:  {}", yes_no(resp.tracing.attached));
    println!("  Command line: {}", yes_no(resp.tracing.command_line));
    if let Some(reason) = &resp.tracing.reason {
        println!("  Reason:       {reason}");
    }
    println!("  Lineage:      {}", yes_no(resp.tracing.lineage));
    if let Some(reason) = &resp.tracing.lineage_reason {
        println!("  Why not:      {reason}");
    }
    println!(
        "  Entries:      {} of {}",
        resp.stats.entries, resp.stats.capacity
    );
    // Evictions are what a bound costs, so they are printed next to the
    // bound rather than left for somebody to find in the JSON.
    println!(
        "  Recorded:     {}  replaced {}  evicted {}  purged {}",
        resp.stats.recorded, resp.stats.replaced, resp.stats.evicted, resp.stats.purged
    );
    println!(
        "  Forks:        {}  ancestors kept {} of {}  evicted {}",
        resp.stats.forks,
        resp.stats.ancestors,
        resp.stats.ancestor_capacity,
        resp.stats.ancestors_evicted
    );

    if resp.processes.is_empty() {
        println!("\nNo process in the table.");
        return Ok(());
    }

    let shown: Vec<_> = if limit == 0 {
        resp.processes.iter().collect()
    } else {
        resp.processes.iter().take(limit).collect()
    };

    println!();
    let mut table = Table::new(&[
        ("PID", Align::Right),
        ("PPID", Align::Right),
        ("UID", Align::Right),
        ("EXECUTABLE", Align::Left),
        ("CONTAINER", Align::Left),
    ]);
    for p in &shown {
        table.row(cells![
            p.pid,
            p.parent_pid
                .map_or_else(|| "-".to_string(), |v| v.to_string()),
            p.uid,
            p.executable(),
            p.container.as_ref().map_or_else(
                || "-".to_string(),
                |c| c.name.clone().unwrap_or_else(|| c.id.clone())
            )
        ]);
    }
    table.print();

    if limit != 0 && resp.processes.len() > shown.len() {
        println!(
            "\n{} more, raise --limit to see them.",
            resp.processes.len() - shown.len()
        );
    }
    Ok(())
}

pub async fn cmd_processes_show(client: &ApiClient, pid: u32, output: OutputFormat) -> Result<()> {
    let resp = client.get_process(pid).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("Process {}", resp.pid);
    println!("  Command:      {}", resp.comm);
    println!("  Executable:   {}", resp.executable());
    println!("  Identity:     {}", resp.identity.kind);
    if let Some(ppid) = resp.parent_pid {
        println!("  Parent:       {ppid}");
    }
    if let Some(cmdline) = &resp.command_line {
        println!("  Command line: {cmdline}");
    }
    println!("  UID / GID:    {} / {}", resp.uid, resp.gid);
    println!("  Cgroup id:    {}", resp.cgroup_id);
    if let Some(container) = &resp.container {
        println!("  Container:    {} ({})", container.id, container.runtime);
        if let Some(name) = &container.name {
            println!("  Name:         {name}");
        }
        if let Some(image) = &container.image {
            println!("  Image:        {image}");
        }
    }
    println!("  Started at:   {} ns", resp.started_at_ns);
    if let Some(ancestry) = &resp.ancestry {
        print_ancestry(ancestry);
    }
    Ok(())
}

/// Print the chain above a process, parent first, marking the ancestors
/// kept after their exit and saying when the chain was cut short.
fn print_ancestry(ancestry: &crate::api_client::ProcessAncestryResponse) {
    if ancestry.ancestors.is_empty() && !ancestry.incomplete && !ancestry.truncated {
        return;
    }
    println!("  Ancestry:");
    for ancestor in &ancestry.ancestors {
        let name = ancestor
            .identity
            .path
            .clone()
            .unwrap_or_else(|| format!("[{}]", ancestor.comm));
        let exited = if ancestor.exited_at_ns.is_some() {
            "  (exited)"
        } else {
            ""
        };
        println!("    {:>7}  {name}{exited}", ancestor.pid);
    }
    if ancestry.incomplete {
        println!("    ...      the table no longer holds the next ancestor");
    }
    if ancestry.truncated {
        println!("    ...      further ancestors are not shown");
    }
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
        ("ADDRESS", Align::Left),
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
            svc.listen_addr.as_deref().unwrap_or("*"),
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
    println!(
        "  Address:   {}",
        svc.listen_addr.as_deref().unwrap_or("* (every address)")
    );
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

pub async fn cmd_lb_bgp(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let status = client.lb_vip_bgp().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("BGP VIP Announcement");
    println!("  Enabled:   {}", yes_no(status.enabled));
    println!("  Exporting: {}", yes_no(status.exporting));
    if let Some(err) = &status.error {
        println!("  Error:     {err}");
    }
    if status.sessions.is_empty() {
        println!("\n  No sessions reported.");
        return Ok(());
    }

    println!();
    let mut table = Table::new(&[
        ("PEER", Align::Left),
        ("STATE", Align::Left),
        ("SINCE", Align::Left),
        ("LAST_ERROR", Align::Left),
    ])
    .indent("  ");
    for s in &status.sessions {
        table.row(cells![
            s.peer,
            s.state,
            s.since,
            s.last_error.as_deref().unwrap_or("-")
        ]);
    }
    table.print();
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
    if let Some(ms) = status.grant_remaining_ms {
        println!("  Grant left:     {}.{:03}s", ms / 1000, ms % 1000);
    }
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

pub async fn cmd_lb_grant(client: &ApiClient, seconds: u32, output: OutputFormat) -> Result<()> {
    let status = client.grant_lb_vip_speaker(seconds).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    if status.is_speaker {
        println!("Speaker for {} VIP(s) for {seconds}s", status.vips.len());
    } else {
        println!("Speaker role released");
    }
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

pub async fn cmd_qos_shaping(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let shaping = client.qos_shaping().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&shaping)?);
        return Ok(());
    }

    println!("Per-workload shaping");
    println!("  Supported: {}", yes_no(shaping.supported));
    println!("  Active:    {}", yes_no(shaping.active));
    if let Some(err) = &shaping.read_error {
        println!("  Read error: {err}");
    }

    if !shaping.interfaces.is_empty() {
        println!();
        let mut table = Table::new(&[
            ("INTERFACE", Align::Left),
            ("ROOT QDISC", Align::Left),
            ("HONOURED", Align::Left),
            ("ERROR", Align::Left),
        ]);
        for iface in &shaping.interfaces {
            table.row(cells![
                iface.name,
                iface.root_qdisc.as_deref().unwrap_or("-"),
                yes_no(iface.honoured),
                iface.error.as_deref().unwrap_or("-")
            ]);
        }
        table.print();
    }

    if shaping.rules.is_empty() {
        println!("\nNo shaping rules configured.");
        return Ok(());
    }

    println!();
    let mut table = Table::new(&[
        ("RULE", Align::Left),
        ("RATE (bps)", Align::Right),
        ("HORIZON(ms)", Align::Right),
        ("WORKLOAD", Align::Left),
    ]);
    for rule in &shaping.rules {
        let workload = [
            rule.unit.as_deref().map(|u| format!("unit={u}")),
            rule.cgroup.as_deref().map(|c| format!("cgroup={c}")),
            rule.container.as_deref().map(|c| format!("container={c}")),
            rule.kubernetes.then(|| "kubernetes".to_string()),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
        table.row(cells![rule.id, rule.rate_bps, rule.horizon_ms, workload]);
    }
    table.print();

    if shaping.cgroups.is_empty() {
        println!("\nNo cgroup is held to a rate.");
        return Ok(());
    }

    println!();
    let mut table = Table::new(&[
        ("CGROUP", Align::Left),
        ("RULE", Align::Left),
        ("RATE (bps)", Align::Right),
        ("ACHIEVED (bps)", Align::Right),
        ("BYTES", Align::Right),
        ("DROPPED", Align::Right),
    ]);
    for shaped in &shaping.cgroups {
        let name = shaped
            .container
            .clone()
            .or_else(|| shaped.cgroup.clone())
            .unwrap_or_else(|| shaped.cgroup_id.to_string());
        let achieved = shaped
            .achieved_bps
            .map_or_else(|| "-".to_string(), |bps| bps.to_string());
        table.row(cells![
            name,
            shaped.rule_id,
            shaped.rate_bps,
            achieved,
            shaped.bytes,
            shaped.dropped_horizon
        ]);
    }
    table.print();
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
        "  {:<12}  {}  {:<18} -> {:<18}  {}{}",
        alert.component,
        severity,
        alert.src_ip_str(),
        alert.dst_ip_str(),
        truncate(&alert.message, 50),
        alert.origin_suffix(),
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

pub async fn cmd_flow_export(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.flow_export_status().await?;
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!(
        "enabled: {}\nsampling: 1 in {}\nactive timeout: {}s\nidle timeout: {}s",
        resp.enabled, resp.sampling, resp.active_timeout_secs, resp.idle_timeout_secs
    );
    println!(
        "table: {} flows capacity, queue {} records, batch {}",
        resp.table_capacity, resp.queue_depth, resp.batch_size
    );
    println!(
        "observed: {}  exported: {}  sampled out: {}  evicted: {}  restarted: {}",
        resp.observed, resp.exported, resp.sampled_out, resp.evicted, resp.restarted
    );
    // Said even at zero: a reader has to be able to tell a queue that never
    // filled from a figure nobody reported.
    println!("dropped by a full queue: {}", resp.queue_drops);

    if resp.sinks.is_empty() {
        println!("\nNo sink configured.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("SINK", Align::Left),
        ("HEALTHY", Align::Right),
        ("SENT", Align::Right),
        ("FAILED", Align::Right),
        ("FAILURES", Align::Right),
        ("DETAIL", Align::Left),
    ]);
    for sink in &resp.sinks {
        let detail = sink.detail.as_deref().unwrap_or("-");
        table.row(cells![
            sink.name,
            if sink.healthy { "yes" } else { "no" },
            sink.records_sent,
            sink.records_failed,
            sink.consecutive_failures,
            detail
        ]);
    }
    table.print();
    Ok(())
}

pub async fn cmd_service_graph(
    client: &ApiClient,
    minutes: u64,
    output: OutputFormat,
) -> Result<()> {
    let resp = client.service_graph(minutes).await?;
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!(
        "last {} min, {} edges, {} requests dropped by a full minute (bound {} edges)",
        resp.minutes,
        resp.edges.len(),
        resp.dropped,
        resp.max_edges_per_minute
    );
    if resp.edges.is_empty() {
        println!("\nNo request seen.");
        return Ok(());
    }

    let end = |end: &crate::api_client::ServiceEndBody| match &end.service {
        Some(service) => format!("{service} ({})", end.address),
        None => end.address.clone(),
    };
    let mut table = Table::new(&[
        ("CLIENT", Align::Left),
        ("SERVER", Align::Left),
        ("PORT", Align::Right),
        ("PROTO", Align::Left),
        ("SEEN FROM", Align::Left),
        ("REQUESTS", Align::Right),
        ("ERRORS", Align::Right),
        ("UNANSWERED", Align::Right),
        ("MEAN MS", Align::Right),
        ("RTT P50 MS", Align::Right),
        ("RTT P99 MS", Align::Right),
    ]);
    for edge in &resp.edges {
        let rtt = |quantile| {
            edge.round_trip
                .as_ref()
                .map_or_else(|| "-".to_string(), |rt| rtt_quantile_ms(rt, quantile))
        };
        let mean = edge.duration_ns_sum.checked_div(edge.answered).map_or_else(
            || "-".to_string(),
            |ns| {
                format!(
                    "{:.2}",
                    std::time::Duration::from_nanos(ns).as_secs_f64() * 1_000.0
                )
            },
        );
        table.row(cells![
            end(&edge.client),
            end(&edge.server),
            edge.server_port,
            edge.protocol,
            edge.observed_from,
            edge.requests,
            edge.errors,
            edge.unanswered,
            mean,
            rtt(0.5),
            rtt(0.99)
        ]);
    }
    table.print();
    Ok(())
}

/// The round-trip time below which `quantile` of the samples fall, read as
/// the upper bound of the bucket crossing it, in milliseconds. A quantile in
/// the last bucket is above its lower bound and is written so.
fn rtt_quantile_ms(rt: &crate::api_client::RoundTripBody, quantile: f64) -> String {
    let total: u64 = rt.buckets.iter().sum();
    if total == 0 {
        return "-".to_string();
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let rank = ((total as f64) * quantile).ceil().max(1.0) as u64;
    let ms = |us: u64| std::time::Duration::from_micros(us).as_secs_f64() * 1_000.0;
    let mut seen = 0_u64;
    let last = rt.buckets.len().saturating_sub(1);
    for (bucket, count) in rt.buckets.iter().enumerate() {
        seen = seen.saturating_add(*count);
        if seen >= rank {
            let shift = u32::try_from(bucket).unwrap_or(u32::MAX);
            if bucket == last {
                let floor = rt
                    .first_bound_us
                    .checked_shl(shift.saturating_sub(1))
                    .unwrap_or(u64::MAX);
                return format!(">{:.2}", ms(floor));
            }
            let bound = rt.first_bound_us.checked_shl(shift).unwrap_or(u64::MAX);
            return format!("{:.2}", ms(bound));
        }
    }
    "-".to_string()
}

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
            ("WORKLOAD", Align::Left),
        ]);
        for c in &conns {
            // A dash rather than a blank, because an empty cell reads as a
            // column the agent forgot to fill: a forwarded flow has no local
            // process and that is an answer.
            let workload = c.workload.as_ref().map_or_else(
                || "-".to_string(),
                crate::api_client::WorkloadResponse::summary,
            );
            table.row(cells![
                c.src_ip,
                c.dst_ip,
                c.src_port,
                c.dst_port,
                c.protocol,
                c.state,
                c.packets_fwd,
                c.packets_rev,
                workload
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

// ── Enhanced Status ─────────────────────────────────────────

/// Read an enricher verdict back as the sentence it means, so a table reader
/// does not have to learn the wire vocabulary.
fn enricher_state(state: &str) -> &str {
    match state {
        "on" => "on",
        "off_no_socket" => "off, no socket",
        "off_not_in_cluster" => "off, not in a cluster",
        "off_unavailable" => "off, unreachable",
        "off_by_configuration" => "off by configuration",
        "off_not_built" => "not in this build",
        "starting" => "starting",
        other => other,
    }
}

fn print_container_coverage(coverage: &crate::api_client::ContainerCoverage) {
    let procfs = if coverage.host_proc {
        "host procfs"
    } else {
        "own procfs"
    };
    println!(
        "  Containers {} ({procfs}), ids {}, docker {}, podman {}, lxc {}, kubernetes {}",
        coverage.proc_root,
        if coverage.resolver { "yes" } else { "no" },
        enricher_state(&coverage.docker),
        coverage
            .podman
            .as_deref()
            .map_or("not reported", enricher_state),
        coverage
            .lxc
            .as_deref()
            .map_or("not reported", enricher_state),
        enricher_state(&coverage.kubernetes),
    );
    for runtime in &coverage.podman_runtimes {
        println!("             {}", podman_runtime_line(runtime));
    }
}

/// One Podman runtime, as the status line under the containers names it.
fn podman_runtime_line(runtime: &crate::api_client::PodmanRuntime) -> String {
    let owner = runtime.uid.map_or_else(
        || "podman root".to_string(),
        |uid| format!("podman uid {uid}"),
    );
    let reach = match runtime.reach.as_str() {
        "reachable" => "named",
        "no_socket" => "unnamed, no socket (podman.socket not enabled, or not mounted)",
        "refused" => "unnamed, the socket refused the agent",
        "unavailable" => "unnamed, the socket did not answer",
        "rootless_off" => "unnamed, rootless runtimes are off by configuration",
        other => other,
    };
    format!("{owner}: {reach} ({})", runtime.socket)
}

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

    // Containers: what this agent can actually say about them, which is what
    // the deployment matrix claims mode by mode.
    if let Some(coverage) = &status.container_coverage {
        print_container_coverage(coverage);
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

pub async fn cmd_ids_suricata(
    client: &ApiClient,
    refusals: bool,
    output: OutputFormat,
) -> Result<()> {
    let report = client.ids_suricata_report().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    if report.rulesets.is_empty() {
        println!("No Suricata ruleset imported.");
        return Ok(());
    }
    print_suricata_rulesets(&report.rulesets, refusals);
    Ok(())
}

/// Compile a ruleset file the way the agent would, with no agent involved,
/// so a ruleset can be judged before it is configured.
pub fn cmd_ids_suricata_check(
    file: &std::path::Path,
    address_vars: &[String],
    port_vars: &[String],
    refusals: bool,
    output: OutputFormat,
) -> Result<()> {
    let text = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let text = String::from_utf8_lossy(&text);
    let vars = domain::ids::suricata::SuricataVars::with_overrides(
        &parse_vars("--address-var", address_vars)?,
        &parse_vars("--port-var", port_vars)?,
    );
    let import = domain::ids::suricata::compile_rulesets(
        [(file.display().to_string(), text.as_ref())],
        &vars,
    );
    let rulesets: Vec<SuricataRulesetResponse> = import
        .rulesets
        .iter()
        .map(suricata_ruleset_response)
        .collect();

    if output == OutputFormat::Json {
        let report = SuricataReportResponse { rulesets };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    print_suricata_rulesets(&rulesets, refusals);
    Ok(())
}

fn parse_vars(flag: &str, raw: &[String]) -> Result<std::collections::BTreeMap<String, String>> {
    raw.iter()
        .map(|entry| {
            let Some((name, value)) = entry.split_once('=') else {
                bail!("{flag} {entry}: expected NAME=VALUE");
            };
            let name = name.trim().trim_start_matches('$');
            if name.is_empty() {
                bail!("{flag} {entry}: the variable has no name");
            }
            Ok((name.to_string(), value.trim().to_string()))
        })
        .collect()
}

fn suricata_ruleset_response(
    import: &domain::ids::suricata::RulesetImport,
) -> SuricataRulesetResponse {
    let report = &import.report;
    SuricataRulesetResponse {
        source: import.source.clone(),
        total: report.total,
        compiled: report.compiled,
        native_rules: report.native_rules,
        disabled: report.disabled,
        refused_share: report.refused_share(),
        refused_by_keyword: report
            .refusals_by_keyword()
            .into_iter()
            .map(|(keyword, count)| SuricataKeywordCount { keyword, count })
            .collect(),
        refused: report
            .refused
            .iter()
            .map(|refusal| SuricataRefusalResponse {
                sid: refusal.sid,
                line: refusal.line,
                keyword: refusal.keyword.clone(),
                reason: refusal.reason.clone(),
            })
            .collect(),
    }
}

fn print_suricata_rulesets(rulesets: &[SuricataRulesetResponse], refusals: bool) {
    let mut table = Table::new(&[
        ("RULESET", Align::Left),
        ("ENABLED", Align::Right),
        ("COMPILED", Align::Right),
        ("NATIVE", Align::Right),
        ("REFUSED", Align::Right),
        ("SHARE", Align::Right),
        ("DISABLED", Align::Right),
    ]);
    for ruleset in rulesets {
        table.row(cells![
            ruleset.source,
            ruleset.total,
            ruleset.compiled,
            ruleset.native_rules,
            ruleset.refused.len(),
            format!("{:.1}%", ruleset.refused_share * 100.0),
            ruleset.disabled
        ]);
    }
    table.print();

    for ruleset in rulesets {
        if ruleset.refused_by_keyword.is_empty() {
            continue;
        }
        println!("\nRefused in {}, by keyword:", ruleset.source);
        let mut by_keyword = Table::new(&[("KEYWORD", Align::Left), ("RULES", Align::Right)]);
        for row in &ruleset.refused_by_keyword {
            by_keyword.row(cells![row.keyword, row.count]);
        }
        by_keyword.print();
        if refusals {
            let mut each = Table::new(&[
                ("LINE", Align::Right),
                ("SID", Align::Right),
                ("KEYWORD", Align::Left),
                ("REASON", Align::Left),
            ]);
            for refusal in &ruleset.refused {
                each.row(cells![
                    refusal.line,
                    refusal
                        .sid
                        .map_or_else(|| "-".to_string(), |sid| sid.to_string()),
                    refusal.keyword,
                    refusal.reason
                ]);
            }
            each.print();
        }
    }
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

/// Print why the kernel dropped packets on this node, busiest first.
pub async fn cmd_ebpf_drops(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.drop_reasons().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    if !resp.counting {
        println!("Kernel drops are not counted on this node.");
        if let Some(reason) = &resp.reason {
            println!("Reason: {reason}");
        }
        return Ok(());
    }
    if let Some(error) = &resp.last_error {
        println!("Last read failed, counts below are the previous ones: {error}");
    }
    if resp.drops.is_empty() {
        println!("No drop counted since the counter was loaded.");
    } else {
        let mut table = Table::new(&[
            ("REASON", Align::Left),
            ("INTERFACE", Align::Left),
            ("PACKETS", Align::Right),
            ("MEANING", Align::Left),
        ]);
        for drop in &resp.drops {
            table.row(cells![
                drop.reason,
                drop.interface,
                drop.packets,
                drop.description.as_deref().unwrap_or("-")
            ]);
        }
        table.print();
    }
    println!("\n{} drop(s) counted.", resp.total);
    if resp.uncounted > 0 {
        println!(
            "{} drop(s) seen but not counted: the kernel-side table is full.",
            resp.uncounted
        );
    }
    Ok(())
}

/// Print the sockets this node accepts traffic on and the workload that
/// bound each, every address first.
pub async fn cmd_exposure_listeners(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.exposure_listeners().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    if !resp.reading {
        println!("The socket hooks are not attached on this node, so its listeners are unknown.");
        return Ok(());
    }
    if resp.listeners.is_empty() {
        println!("No listener recorded since the socket hooks attached.");
        return Ok(());
    }
    let mut table = Table::new(&[
        ("PROTO", Align::Left),
        ("ADDRESS", Align::Left),
        ("PORT", Align::Right),
        ("SCOPE", Align::Left),
        ("CLASS", Align::Left),
        ("ALLOWED", Align::Left),
        ("ACCEPTED", Align::Right),
        ("PID", Align::Right),
        ("EXECUTABLE", Align::Left),
        ("POD", Align::Left),
        ("UNIT", Align::Left),
    ]);
    for listener in &resp.listeners {
        table.row(cells![
            listener.protocol,
            listener.address,
            listener.port.to_string(),
            listener.scope,
            listener.class,
            allowed_sources(listener),
            listener
                .accepted
                .map_or_else(|| "-".to_string(), |n| n.to_string()),
            listener.pid.to_string(),
            listener.executable.as_deref().unwrap_or("-"),
            listener.pod.as_deref().unwrap_or("-"),
            listener.unit.as_deref().unwrap_or("-")
        ]);
    }
    table.print();
    Ok(())
}

/// Who the packet firewall lets through to a listener, in one cell.
fn allowed_sources(listener: &crate::api_client::ListenerEntry) -> String {
    if !listener.reachable {
        return "none".to_string();
    }
    if listener.allowed_from.is_empty() {
        return "any".to_string();
    }
    listener.allowed_from.join(", ")
}

/// Print the packet sockets open on this node, who holds them and what
/// filter is attached to them.
pub async fn cmd_ebpf_raw_sockets(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.raw_sockets().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    if !resp.reading {
        println!("The packet socket inventory is turned off on this node.");
        return Ok(());
    }
    if let Some(error) = &resp.last_error {
        println!("Last reading failed, sockets below are the previous ones: {error}");
    }
    if resp.sockets.is_empty() {
        println!("No packet socket open on this node.");
        return Ok(());
    }
    let mut table = Table::new(&[
        ("PID", Align::Right),
        ("EXECUTABLE", Align::Left),
        ("POD", Align::Left),
        ("KIND", Align::Left),
        ("PROTOCOL", Align::Left),
        ("INTERFACE", Align::Left),
        ("NETNS", Align::Left),
        ("FILTER", Align::Left),
    ]);
    for socket in &resp.sockets {
        let filter = match socket.filter_instructions {
            Some(n) => format!("{} ({n} insns)", socket.filter),
            None => socket.filter.clone(),
        };
        table.row(cells![
            socket
                .pid
                .map_or_else(|| "-".to_string(), |p| p.to_string()),
            socket.executable.as_deref().unwrap_or("-"),
            socket.pod.as_deref().unwrap_or("-"),
            socket.kind,
            socket.protocol,
            socket.interface,
            if socket.host_netns {
                "host".to_string()
            } else {
                socket.netns.to_string()
            },
            filter
        ]);
    }
    table.print();
    println!(
        "\n{} packet socket(s), read through {}.",
        resp.sockets.len(),
        resp.source.as_deref().unwrap_or("-")
    );
    Ok(())
}

/// Print the last comparison of the socket listings with a bind probe: what
/// explained each refused bind, and the ports nothing explained.
pub async fn cmd_ebpf_hidden_ports(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.hidden_ports().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    if !resp.reading {
        println!("The hidden port sweep is turned off on this node.");
        return Ok(());
    }
    if resp.scanned_at_ns == 0 {
        println!("The first sweep has not finished yet.");
        return Ok(());
    }
    if let Some(error) = &resp.last_error {
        println!("Last sweep failed, the result below is the previous one: {error}");
    }
    let c = &resp.counts;
    println!(
        "{} port(s) probed in {} namespace(s), read through {}.",
        resp.probed_ports,
        c.namespaces,
        resp.source.as_deref().unwrap_or("-")
    );
    println!(
        "{} bind(s) refused: {} by a listener, {} by TIME_WAIT, {} by another socket, \
         {} not confirmed by the second reading, {} hidden. {} bind(s) could not be tried.",
        c.refused,
        c.explained_by_listener,
        c.explained_by_time_wait,
        c.explained_by_other_socket,
        c.unconfirmed,
        c.hidden,
        c.unprobed
    );
    for ns in &resp.unreachable {
        println!("Namespace {} not swept: {}", ns.netns, ns.reason);
    }
    if resp.hidden.is_empty() {
        println!("No hidden port.");
        return Ok(());
    }
    let mut table = Table::new(&[
        ("NETNS", Align::Left),
        ("TRANSPORT", Align::Left),
        ("ADDRESS", Align::Left),
        ("PORT", Align::Right),
    ]);
    for port in &resp.hidden {
        table.row(cells![
            if port.host_netns {
                "host".to_string()
            } else {
                port.netns.to_string()
            },
            port.transport,
            port.address,
            port.port
        ]);
    }
    table.print();
    Ok(())
}

/// Print the last comparison of the listing of `/proc` with a signal sweep:
/// what explained each pid that answered and was not listed, and the
/// processes nothing explained.
pub async fn cmd_ebpf_hidden_processes(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.hidden_processes().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    if !resp.reading {
        println!("The hidden process sweep is turned off on this node.");
        return Ok(());
    }
    if resp.scanned_at_ns == 0 {
        println!("The first sweep has not finished yet.");
        return Ok(());
    }
    if let Some(error) = &resp.last_error {
        println!("Last sweep failed, the result below is the previous one: {error}");
    }
    let c = &resp.counts;
    println!(
        "{} pid(s) signalled of {} at {} a second, {} thread group(s) listed, read through {}.",
        c.probed,
        c.pid_space,
        resp.pids_per_second,
        c.listed,
        resp.source.as_deref().unwrap_or("-")
    );
    println!(
        "{} pid(s) answered and were not listed: {} thread(s) of a listed group, {} exiting, \
         {} not confirmed by the second reading, {} reused, {} hidden.",
        c.answered_unlisted,
        c.explained_by_thread,
        c.explained_by_exit,
        c.unconfirmed,
        c.reused,
        c.hidden
    );
    if resp.hidden.is_empty() {
        println!("No hidden process.");
        return Ok(());
    }
    let mut table = Table::new(&[("PID", Align::Right), ("COMMAND", Align::Left)]);
    for process in &resp.hidden {
        table.row(cells![process.pid, process.comm.as_deref().unwrap_or("-")]);
    }
    table.print();
    Ok(())
}

/// The short name of a root: the host, a container by the first twelve
/// characters of its id, or the pid whose root no runtime names.
fn root_label(root: &crate::api_client::PackageRootEntry) -> String {
    match (root.kind.as_str(), root.container_id.as_deref()) {
        ("host", _) => "host".to_string(),
        ("container", Some(id)) => id.chars().take(12).collect(),
        _ => format!("pid {}", root.pid),
    }
}

/// Print what the package databases say is installed, root by root, and
/// each database that could not be read with the reason.
pub async fn cmd_surface_packages(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.surface_packages().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    if !resp.reading {
        println!("The package inventory is turned off on this node.");
        return Ok(());
    }
    if resp.scanned_at_ns == 0 {
        println!("The first reading has not finished yet.");
        return Ok(());
    }
    if let Some(error) = &resp.last_error {
        println!("Last reading failed, the result below is the previous one: {error}");
    }
    println!(
        "{} root(s) read through {}.",
        resp.roots.len(),
        resp.source.as_deref().unwrap_or("-")
    );
    if resp.roots_not_read > 0 {
        println!("{} more root(s) were not read.", resp.roots_not_read);
    }
    for root in &resp.roots {
        let label = root_label(root);
        if let Some(error) = &root.error {
            println!("{label}: could not be read: {error}");
        }
        for db in &root.databases {
            if let Some(reason) = &db.unreadable {
                println!(
                    "{label}: {} database {} not read: {reason}",
                    db.manager, db.path
                );
            }
        }
    }
    let mut table = Table::new(&[
        ("ROOT", Align::Left),
        ("MANAGER", Align::Left),
        ("PACKAGE", Align::Left),
        ("VERSION", Align::Left),
        ("ARCH", Align::Left),
        ("STATE", Align::Left),
        ("FILES", Align::Right),
    ]);
    let mut rows = 0usize;
    for root in &resp.roots {
        let label = root_label(root);
        for db in &root.databases {
            for p in &db.packages {
                rows += 1;
                table.row(cells![
                    label,
                    db.manager,
                    p.name,
                    p.version,
                    p.arch.as_deref().unwrap_or("-"),
                    p.state,
                    p.files.map_or_else(|| "-".to_string(), |n| n.to_string())
                ]);
            }
        }
    }
    if rows == 0 {
        println!("No package database was found in any root.");
        return Ok(());
    }
    table.print();
    Ok(())
}

/// Print the eBPF programs on the network path that the agent did not load,
/// where they run and who holds them.
pub async fn cmd_ebpf_foreign_programs(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.foreign_programs().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    if !resp.reading {
        println!("The network program inventory is turned off on this node.");
        return Ok(());
    }
    if let Some(error) = &resp.last_error {
        println!("Last reading failed, programs below are the previous ones: {error}");
    }
    if resp.programs.is_empty() {
        println!(
            "No eBPF program on the network path besides the agent's own {}.",
            resp.own_programs
        );
        return Ok(());
    }
    let mut table = Table::new(&[
        ("PROG", Align::Right),
        ("NAME", Align::Left),
        ("TYPE", Align::Left),
        ("PLACE", Align::Left),
        ("HELD BY", Align::Left),
    ]);
    for program in &resp.programs {
        let held_by = if program.holders.is_empty() {
            "-".to_string()
        } else {
            program
                .holders
                .iter()
                .map(|h| {
                    let who = h.pod.as_deref().or(h.executable.as_deref()).unwrap_or("?");
                    format!("{} ({who})", h.pid)
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        table.row(cells![
            program.prog_id.to_string(),
            program.name,
            program.prog_type,
            program.position.map_or_else(
                || program.place.clone(),
                |at| format!("{} (position {at})", program.place)
            ),
            held_by
        ]);
    }
    table.print();
    println!(
        "\n{} foreign program(s) and {} of the agent's own, read through {}.",
        resp.programs.len(),
        resp.own_programs,
        resp.source.as_deref().unwrap_or("-")
    );
    Ok(())
}

/// The workload firewall's hooks, and the rule on the DNS ports when one is
/// configured.
fn print_workload_firewall(wf: &crate::api_client::WorkloadFirewallReport) {
    println!("\nWorkload firewall");
    println!("  Attached:   {}", yes_no(wf.attached));
    println!("  Cgroup:     {}", wf.cgroup);
    println!("  Brokered:   {}", yes_no(wf.brokered));
    if !wf.hooks.is_empty() {
        println!("  Hooks:      {}", wf.hooks.join(", "));
    }
    if let Some(reason) = &wf.reason {
        println!("  Reason:     {reason}");
    }
    if let Some(dns) = &wf.dns_rule {
        print_dns_rule(dns);
    }
}

/// Which processes may resolve, and what a rule on the DNS ports leaves out.
fn print_dns_rule(dns: &crate::api_client::DnsRuleReport) {
    let ports: Vec<String> = dns.ports.iter().map(u16::to_string).collect();
    println!("  DNS rule:   {} on ports {}", dns.mode, ports.join(", "));
    if !dns.resolvers.is_empty() {
        println!("  Resolvers:  {}", dns.resolvers.join(", "));
    }
    println!("  Clients:    {}", dns.clients);
    for sentence in &dns.not_covered {
        println!("  Not seen:   {sentence}");
    }
}

/// Print what this node can do to the process behind a flow.
///
/// The signal, the window and the size of the protected set are printed only
/// when something is armed, because a figure beside a capability that is off
/// reads as a capability that is on.
fn print_process_signal(report: &crate::api_client::ProcessSignalReport) {
    println!("\nStopping a process");
    println!("  Armed:      {}", yes_no(report.attached));
    if report.attached {
        println!("  Signal:     {}", report.signal);
        println!("  Window:     {} ms", report.window_ms);
        println!("  Protected:  {} pids", report.protected);
    }
    if let Some(reason) = &report.reason {
        println!("  Reason:     {reason}");
    }
}

/// Print whether an LSM program can attach on the host, and the remedy when
/// it cannot.
fn print_bpf_lsm(report: &crate::api_client::BpfLsmReport) {
    println!("\nBPF LSM");
    println!("  Active:     {}", yes_no(report.active));
    let built = match report.built {
        Some(built) => yes_no(built),
        None => "unknown",
    };
    println!("  Built in:   {built}");
    if !report.modules.is_empty() {
        println!("  Modules:    {}", report.modules.join(","));
    }
    if let Some(reason) = &report.reason {
        println!("  Reason:     {reason}");
    }
    if let Some(remedy) = &report.remedy {
        println!("  Remedy:     {remedy}");
    }
}

/// Print the two blocks that depend on the BPF LSM, saying so when an older
/// agent does not report one.
fn print_lsm_blocks(resp: &crate::api_client::KernelFeaturesResponse) {
    match &resp.bpf_lsm {
        Some(report) => print_bpf_lsm(report),
        None => println!("\nBPF LSM\n  Not reported by this agent."),
    }
    match &resp.network_executables {
        Some(report) => print_network_executables(report),
        None => println!("\nNetwork executables\n  Not reported by this agent."),
    }
    match &resp.self_protection {
        Some(report) => print_self_protection(report),
        None => println!("\nSelf-protection\n  Not reported by this agent."),
    }
    match &resp.file_kfuncs {
        Some(report) => print_file_kfuncs(report),
        None => println!("\nFile kfuncs\n  Not reported by this agent."),
    }
    match &resp.kfunc_features {
        Some(report) => print_kfunc_features(report),
        None => println!("\nKernel facts not yet used\n  Not reported by this agent."),
    }
}

/// Print each kernel fact no shipped program uses yet: whether this host
/// offers it, how that was established, and what it would be used for.
fn print_kfunc_features(report: &crate::api_client::KfuncFeaturesReport) {
    println!("\nKernel facts not yet used");
    if !report.probed {
        println!("  Not probed: startup has not run the probe.");
        return;
    }
    for feature in &report.features {
        let state = match (feature.usable, feature.load_tested) {
            (Some(true), _) => "confirmed by a load",
            (Some(false), _) => "not available",
            (None, false) if feature.kfuncs.iter().all(|k| k.declared == Some(true)) => {
                "declared, not confirmed"
            }
            (None, _) => "not probed",
        };
        println!("  {:<24} {state}", feature.name);
        println!("    For: {}", feature.consumer);
        if feature.usable != Some(true)
            && let Some(reason) = &feature.reason
        {
            println!("    {reason}");
        }
    }
}

/// Print whether the file kfuncs are usable, one line per kfunc, with the
/// condition that failed where one did.
fn print_file_kfuncs(report: &crate::api_client::FileKfuncReport) {
    println!("\nFile kfuncs");
    let sleepable = match report.sleepable_lsm {
        Some(loads) => yes_no(loads),
        None => "not probed",
    };
    println!("  Sleepable LSM: {sleepable}");
    if let Some(reason) = &report.sleepable_reason {
        println!("  Reason:        {reason}");
    }
    for kfunc in &report.kfuncs {
        let state = match (kfunc.usable, kfunc.declared) {
            (true, _) => "usable",
            (false, Some(true)) => "declared, not usable",
            (false, Some(false)) => "not declared",
            (false, None) => "unknown",
        };
        println!("  {:<24} {state}", kfunc.name);
        if !kfunc.usable
            && let Some(reason) = &kfunc.reason
            && report.sleepable_reason.as_deref() != Some(reason.as_str())
        {
            println!("    {reason}");
        }
    }
    if let Some(remedy) = &report.remedy {
        println!("  Remedy:        {remedy}");
    }
}

/// Print whether other tasks are refused the agent's maps and links.
fn print_self_protection(report: &crate::api_client::SelfProtectionReport) {
    println!("\nSelf-protection");
    println!("  Protected:  {}", yes_no(report.protected));
    if report.protected {
        println!("  Maps:       {}", report.maps);
        println!("  Links:      {}", report.links);
        println!("  Allowed:    {} thread groups", report.tasks);
    }
    if let Some(reason) = &report.reason {
        println!("  Reason:     {reason}");
    }
}

/// Print whether the kernel decides which executables reach the network.
fn print_network_executables(report: &crate::api_client::NetworkExecutablesReport) {
    println!("\nNetwork executables");
    println!("  Attached:   {}", yes_no(report.attached));
    if report.attached {
        let mode = if report.enforcing {
            "enforce"
        } else {
            "observe"
        };
        println!("  Mode:       {mode}");
        println!("  Listed:     {} executables", report.executables);
    }
    if let Some(reason) = &report.reason {
        println!("  Reason:     {reason}");
    }
}

/// Answer for the host this runs on, with no agent running and nothing
/// configured: whether an LSM program could attach here. It reads the same
/// two files the agent reads, so it cannot disagree with what the agent
/// would report once installed.
pub fn cmd_ebpf_host_check(output: OutputFormat) -> Result<()> {
    let report = crate::api_client::BpfLsmReport::from(adapters::ebpf::lsm_probe::status());
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    print_bpf_lsm(&report);
    Ok(())
}

/// Print what the node can do to a workload short of stopping it.
///
/// The window and the protected count are printed only when something is
/// armed, for the same reason as the block above. Whether the cut reaches the
/// flows already open is printed either way, because that is the line between
/// a workload off the network and one that merely opens nothing new.
fn print_quarantine(report: &crate::api_client::QuarantineReport) {
    println!("\nQuarantining a workload");
    println!("  Armed:      {}", yes_no(report.armed));
    println!("  Cuts flows: {}", yes_no(report.tears_down_flows));
    if report.armed {
        println!("  Window:     {} ms", report.window_ms);
        println!("  Protected:  {} cgroups", report.protected);
    }
    if let Some(reason) = &report.reason {
        println!("  Reason:     {reason}");
    }
}

pub async fn cmd_ebpf_coverage(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.ebpf_coverage().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("Pod coverage on this node");
    println!("  Uplinks attached:  {}", yes_no(resp.uplinks_attached));
    println!("  Encapsulated:      {}", yes_no(resp.encapsulated));
    println!(
        "  Pods:              {} uncovered, {} partial, {} full",
        resp.uncovered, resp.partial, resp.full
    );
    if resp.links_without_pod > 0 {
        println!("  Links naming no pod: {}", resp.links_without_pod);
    }
    println!(
        "  Pod profile:       {}",
        if resp.pod_profile_recommended == 0 {
            "not needed, no gap it closes beyond loopback".to_string()
        } else {
            format!(
                "would close a gap in {} pods (marked *)",
                resp.pod_profile_recommended
            )
        }
    );
    if resp.pods.is_empty() {
        println!("\nNo pod is scheduled on this node.");
        return Ok(());
    }

    println!();
    let mut table = Table::new(&[
        ("NAMESPACE", Align::Left),
        ("POD", Align::Left),
        ("COVERAGE", Align::Left),
        ("INTERFACES", Align::Left),
        ("NOT OBSERVED", Align::Left),
    ]);
    for pod in &resp.pods {
        let interfaces = if pod.host_network {
            "host network".to_string()
        } else if pod.interfaces.is_empty() {
            "-".to_string()
        } else {
            pod.interfaces
                .iter()
                .map(|i| {
                    let state = if i.attached { "attached" } else { "left" };
                    format!("{} ({}, {state})", i.name, i.kind)
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        let gaps = pod
            .classes
            .iter()
            .filter_map(|c| c.gap.as_ref().map(|gap| format!("{}: {gap}", c.class)))
            .collect::<Vec<_>>()
            .join(", ");
        let name = if pod.pod_profile_recommended {
            format!("{} *", pod.name)
        } else {
            pod.name.clone()
        };
        table.row(cells![pod.namespace, name, pod.level, interfaces, gaps]);
    }
    table.print();
    Ok(())
}

pub async fn cmd_ebpf_guests(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.guests().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!(
        "Guests on this host: {} named, {} unnamed",
        resp.named, resp.unnamed
    );
    if resp.guests.is_empty() {
        println!("\nNo tap, macvtap or KubeVirt launcher link is on this host.");
        return Ok(());
    }

    println!();
    let mut table = Table::new(&[
        ("INTERFACE", Align::Left),
        ("KIND", Align::Left),
        ("ATTACHED", Align::Left),
        ("GUEST", Align::Left),
        ("ID", Align::Left),
        ("SOURCE", Align::Left),
        ("TAGS", Align::Left),
        ("PROTECTED", Align::Left),
    ]);
    for entry in &resp.guests {
        let (name, id, source, tags) = match &entry.guest {
            Some(g) => (
                g.name.clone(),
                g.id.clone(),
                g.source.clone(),
                if g.tags.is_empty() {
                    "-".to_string()
                } else {
                    g.tags.join(",")
                },
            ),
            None => (
                format!("unnamed: {}", entry.unnamed.as_deref().unwrap_or("-")),
                "-".to_string(),
                "-".to_string(),
                "-".to_string(),
            ),
        };
        table.row(cells![
            entry.interface,
            entry.kind,
            yes_no(entry.attached),
            name,
            id,
            source,
            tags,
            if entry.protection.covered.is_empty() {
                "none".to_string()
            } else {
                entry.protection.covered.join(",")
            }
        ]);
    }
    table.print();
    for entry in &resp.guests {
        if let Some(reason) = &entry.reason {
            println!("  {}: {reason}", entry.interface);
        }
    }
    let mut said: Vec<&str> = Vec::new();
    for entry in &resp.guests {
        let reason = entry.protection.reason.as_str();
        if !said.contains(&reason) {
            println!("  Protection: {reason}");
            said.push(reason);
        }
    }
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

    println!("\nProcess tracing");
    println!("  Attached:   {}", yes_no(resp.process_tracing.attached));
    println!(
        "  Cmdline:    {}",
        yes_no(resp.process_tracing.command_line)
    );
    if !resp.process_tracing.tracepoints.is_empty() {
        println!(
            "  Hooks:      {}",
            resp.process_tracing.tracepoints.join(", ")
        );
    }
    if let Some(reason) = &resp.process_tracing.reason {
        println!("  Reason:     {reason}");
    }
    println!("  Lineage:    {}", yes_no(resp.process_tracing.lineage));
    if let Some(reason) = &resp.process_tracing.lineage_reason {
        println!("  Why not:    {reason}");
    }

    print_workload_firewall(&resp.workload_firewall);

    print_process_signal(&resp.process_signal);
    print_quarantine(&resp.quarantine);
    print_lsm_blocks(&resp);

    println!("\nSocket attribution");
    println!("  Attached:   {}", yes_no(resp.attribution.attached));
    println!("  Cgroup:     {}", resp.attribution.cgroup);
    println!("  Brokered:   {}", yes_no(resp.attribution.brokered));
    if !resp.attribution.hooks.is_empty() {
        println!("  Hooks:      {}", resp.attribution.hooks.join(", "));
    }
    if let Some(reason) = &resp.attribution.reason {
        println!("  Reason:     {reason}");
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

pub async fn cmd_dlp_scope(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let scope = client.dlp_scope().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&scope)?);
        return Ok(());
    }

    println!("DLP scope");
    println!("  Probes armed:    {}", yes_no(scope.enabled));
    println!("  Mode:            {}", scope.mode);
    println!("  Selectors:       {}", scope.selectors);
    println!("  Allowed cgroups: {}", scope.allowed_cgroups);
    if scope.mode == "all" {
        println!("\nEvery task this agent has a probe on is read.");
        return Ok(());
    }

    if scope.in_scope.is_empty() {
        println!("\nNo workload is in scope, so no plaintext is read.");
    } else {
        println!("\nIn scope ({}):", scope.in_scope.len());
        let mut table = Table::new(&[
            ("WORKLOAD", Align::Left),
            ("CGROUP", Align::Left),
            ("RULE", Align::Left),
        ]);
        for workload in &scope.in_scope {
            table.row(cells![
                workload.label(),
                workload.cgroup.as_deref().unwrap_or("-"),
                workload.rule
            ]);
        }
        table.print();
    }

    if !scope.excluded.is_empty() {
        println!("\nExcluded ({}):", scope.excluded.len());
        let mut table = Table::new(&[("WORKLOAD", Align::Left), ("BY RULE", Align::Left)]);
        for workload in &scope.excluded {
            table.row(cells![workload.label(), workload.rule]);
        }
        table.print();
    }

    // The point of the route: a rule that reads nothing is a fence nobody
    // aimed, and on a typo in a pod name that is DLP silently off.
    if scope.unmatched.is_empty() {
        println!("\nEvery rule matched at least one workload.");
    } else {
        println!("\nRules matching nothing ({}):", scope.unmatched.len());
        for finding in &scope.unmatched {
            println!(
                "  {} ({}, {}): {}",
                finding.rule, finding.action, finding.selector, finding.reason
            );
        }
    }

    println!(
        "\n{} workload(s) seen and named by no rule. Resolved at epoch {}.",
        scope.unselected, scope.refreshed_unix
    );
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

pub async fn cmd_tls_handshakes(
    client: &ApiClient,
    output: OutputFormat,
    limit: usize,
) -> Result<()> {
    let resp = client.tls_handshakes(limit).await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    if !resp.recording {
        println!("This agent does not read TLS handshakes.");
        return Ok(());
    }
    if resp.handshakes.is_empty() {
        println!("No TLS handshake seen yet.");
        return Ok(());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let mut table = Table::new(&[
        ("CLIENT", Align::Left),
        ("SERVER", Align::Left),
        ("VERSION", Align::Left),
        ("GROUP", Align::Left),
        ("CIPHER", Align::Left),
        ("POSTURE", Align::Left),
        ("CERTIFICATE", Align::Left),
    ]);
    for hs in &resp.handshakes {
        let group = match (&hs.group_name, hs.group) {
            (Some(name), _) => name.clone(),
            (None, Some(code)) => format!("0x{code:04x}"),
            (None, None) => "-".to_string(),
        };
        table.row(cells![
            format!("{}:{}", hs.client, hs.client_port),
            format!("{}:{}", hs.server, hs.server_port),
            hs.version_name
                .clone()
                .unwrap_or_else(|| format!("0x{:04x}", hs.version)),
            group,
            hs.cipher_name
                .clone()
                .unwrap_or_else(|| format!("0x{:04x}", hs.cipher)),
            hs.posture,
            certificate_cell(&hs.certificate, now),
        ]);
    }
    table.print();
    Ok(())
}

pub async fn cmd_tls_posture(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.tls_posture().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    let totals = &resp.totals;
    println!("Network Cryptography");
    println!("  Connections:   {}", totals.connections);
    println!(
        "  Post-quantum:  {}",
        count_cell(totals.post_quantum, totals.shares.post_quantum)
    );
    println!(
        "  Classical:     {}",
        count_cell(totals.classical, totals.shares.classical)
    );
    println!(
        "  Legacy TLS:    {}",
        count_cell(totals.legacy_tls, totals.shares.legacy_tls)
    );
    println!("  Clear text:    {}", clear_text_cell(totals));
    if resp.evicted_edges > 0 {
        println!(
            "  {} edge(s) dropped to make room for newer ones.",
            resp.evicted_edges
        );
    }
    if resp.edges.is_empty() {
        println!("\nNo connection counted yet.");
        return Ok(());
    }

    let end = |end: &crate::api_client::ServiceEndBody| match &end.service {
        Some(service) => format!("{service} ({})", end.address),
        None => end.address.clone(),
    };
    let mut table = Table::new(&[
        ("CLIENT", Align::Left),
        ("SERVER", Align::Left),
        ("PORT", Align::Right),
        ("CONNS", Align::Right),
        ("POST-QUANTUM", Align::Right),
        ("CLASSICAL", Align::Right),
        ("LEGACY TLS", Align::Right),
        ("CLEAR TEXT", Align::Left),
    ]);
    for edge in &resp.edges {
        let c = &edge.counts;
        table.row(cells![
            end(&edge.client),
            end(&edge.server),
            edge.server_port,
            c.connections,
            count_cell(c.post_quantum, c.shares.post_quantum),
            count_cell(c.classical, c.shares.classical),
            count_cell(c.legacy_tls, c.shares.legacy_tls),
            clear_text_cell(c),
        ]);
    }
    println!();
    table.print();
    Ok(())
}

/// A count with its share of the connections, as a whole percentage.
fn count_cell(count: u64, share: f64) -> String {
    format!("{count} ({:.0}%)", share * 100.0)
}

/// The clear-text count with its share and the protocols it was read in.
fn clear_text_cell(counts: &crate::api_client::PostureCountsBody) -> String {
    let cell = count_cell(counts.clear_text, counts.shares.clear_text);
    if counts.clear_text_protocols.is_empty() {
        return cell;
    }
    let protocols: Vec<String> = counts
        .clear_text_protocols
        .iter()
        .map(|(protocol, n)| format!("{protocol} {n}"))
        .collect();
    format!("{cell} {}", protocols.join(", "))
}

/// What the certificate column says: why nothing is known, or how far its
/// end of validity is from now.
fn certificate_cell(cert: &crate::api_client::CertificateBody, now: i64) -> String {
    match (cert.state.as_str(), cert.not_after) {
        ("not_observable", _) => "not observable (TLS 1.3)".to_string(),
        ("read", Some(not_after)) => {
            let days = (not_after - now).div_euclid(86_400);
            if not_after < now {
                format!("expired {} days ago", -days)
            } else {
                format!("expires in {days} days")
            }
        }
        _ => "not captured".to_string(),
    }
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

// ── Packet trace ─────────────────────────────────────────

/// `trace` - what the loaded programs decide for one crafted packet.
pub async fn cmd_trace(client: &ApiClient, body: &TraceBody, output: OutputFormat) -> Result<()> {
    let report = client.trace(body).await?;
    print_trace(&report, output)
}

fn print_trace(report: &TraceResponse, output: OutputFormat) -> Result<()> {
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    let ports = if report.protocol == "icmp" {
        String::new()
    } else {
        format!(" {} -> {}", report.src_port, report.dst_port)
    };
    println!(
        "{} {} -> {}{} ({})",
        report.protocol.to_uppercase(),
        report.src_ip,
        report.dst_ip,
        ports,
        report.direction
    );
    if report.stages.is_empty() {
        println!("No stage recorded a verdict for this packet.");
    } else {
        let mut table = Table::new(&[
            ("STAGE", Align::Left),
            ("HOOK", Align::Left),
            ("VERDICT", Align::Left),
            ("REASON", Align::Left),
            ("RULE", Align::Left),
            ("DETAIL", Align::Left),
        ]);
        for stage in &report.stages {
            let rule = match (&stage.rule, stage.rule_id) {
                (Some(name), _) => name.clone(),
                (None, Some(id)) => format!("#{id}"),
                (None, None) => "-".to_string(),
            };
            table.row(cells![
                stage.stage,
                stage.hook,
                stage.verdict,
                stage.reason,
                rule,
                stage.detail.as_deref().unwrap_or("-")
            ]);
        }
        table.print();
    }
    match &report.stopped_at {
        Some(stage) => println!("Stopped at {stage}: {}.", report.verdict),
        None => println!("Went through every loaded stage."),
    }
    for dep in &report.state_dependent {
        println!(
            "Depends on state at {}: {}. Another packet of this five-tuple may be decided otherwise.",
            dep.stage, dep.depends_on
        );
    }
    if !report.not_loaded.is_empty() {
        println!(
            "Not loaded, so not asked: {}.",
            report.not_loaded.join(", ")
        );
    }
    Ok(())
}

// ── Network policy ───────────────────────────────────────

/// `netpol replay` - what proposed policies would refuse of the tracked
/// connections.
pub async fn cmd_netpol_replay(
    client: &ApiClient,
    file: &str,
    limit: Option<usize>,
    output: OutputFormat,
) -> Result<()> {
    let manifests = if file == "-" {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
            .context("reading the manifests from standard input")?;
        text
    } else {
        std::fs::read_to_string(file).with_context(|| format!("reading {file}"))?
    };
    let report = client
        .replay_netpol(&NetpolReplayBody { manifests, limit })
        .await?;
    print_netpol_replay(&report, output)
}

fn print_netpol_replay(report: &NetpolReplayResponse, output: OutputFormat) -> Result<()> {
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    println!(
        "{} connections read, {} with a pod at one end: {} newly refused, {} refused already.",
        report.flows, report.judged, report.newly_refused, report.still_refused
    );
    // No connection with a pod at either end means nothing was checked, which
    // is not the same answer as a proposal that refuses nothing.
    if report.judged == 0 {
        println!("No tracked connection had a pod at either end, so nothing was checked.");
        return Ok(());
    }
    if report.workloads.is_empty() {
        println!("Nothing tracked on this node would be refused.");
        return Ok(());
    }
    let mut table = Table::new(&[
        ("NAMESPACE", Align::Left),
        ("POD", Align::Left),
        ("DIRECTION", Align::Left),
        ("PEER", Align::Left),
        ("PROTO", Align::Left),
        ("PORT", Align::Right),
        ("FLOWS", Align::Right),
        ("TODAY", Align::Left),
    ]);
    for workload in &report.workloads {
        for flow in &workload.refused {
            let proto = match flow.protocol {
                6 => "TCP",
                17 => "UDP",
                132 => "SCTP",
                1 => "ICMP",
                58 => "ICMPv6",
                _ => "OTHER",
            };
            table.row(cells![
                workload.namespace,
                workload.pod,
                flow.direction,
                flow.peer,
                proto,
                flow.port,
                flow.flows,
                if flow.already_refused {
                    "refused"
                } else {
                    "allowed"
                }
            ]);
        }
    }
    table.print();
    Ok(())
}

// ── Learning mode ────────────────────────────────────────

/// `learning start` - open a window.
pub async fn cmd_learning_start(
    client: &ApiClient,
    duration: u64,
    cgroup: Option<String>,
    exe: Vec<String>,
    unit: Vec<String>,
    container: Vec<String>,
    output: OutputFormat,
) -> Result<()> {
    let scope = learning_scope(cgroup, exe, unit, container);
    let body = StartLearningBody {
        scope,
        duration_secs: duration,
    };
    let session = client.start_learning(&body).await?;
    print_learning_session(&session, output)
}

/// `learning list` - the windows this node remembers.
pub async fn cmd_learning_list(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let sessions = client.learning_sessions().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&sessions)?);
        return Ok(());
    }

    if sessions.is_empty() {
        println!("No window has been opened on this node.");
        return Ok(());
    }

    let mut table = Table::new(&[
        ("ID", Align::Left),
        ("STATUS", Align::Left),
        ("SCOPE", Align::Left),
        ("ELAPSED", Align::Right),
        ("REMAINING", Align::Right),
        ("EDGES", Align::Right),
        ("GAP", Align::Right),
    ]);
    for session in &sessions {
        table.row(cells![
            session.id,
            session.status,
            session.scope_description,
            format!("{}s", session.elapsed_secs),
            format!("{}s", session.remaining_secs),
            session.edges,
            format!("{}s", session.gap_secs)
        ]);
    }
    table.print();
    Ok(())
}

/// `learning status` - one window, the open one when no id is given.
pub async fn cmd_learning_status(
    client: &ApiClient,
    id: Option<String>,
    output: OutputFormat,
) -> Result<()> {
    let id = resolve_learning_id(client, id).await?;
    let session = client.learning_session(&id).await?;
    print_learning_session(&session, output)
}

/// `learning stop` - close a window before its time is up.
pub async fn cmd_learning_stop(
    client: &ApiClient,
    id: Option<String>,
    output: OutputFormat,
) -> Result<()> {
    let id = resolve_learning_id(client, id).await?;
    let session = client.stop_learning(&id).await?;
    print_learning_session(&session, output)
}

/// Write the allow-list a window describes.
///
/// The document goes to standard output so it can be piped into a review,
/// and to a file when one is named. Nothing is applied here: the agent
/// loads this document the day somebody puts it in its configuration, and
/// every rule in it is in observe mode until somebody changes that.
pub async fn cmd_learning_policy(
    client: &ApiClient,
    id: Option<String>,
    output_file: Option<PathBuf>,
    output: OutputFormat,
) -> Result<()> {
    let id = resolve_learning_id(client, id).await?;
    let policy = client.learning_policy(&id).await?;
    if let Some(path) = output_file {
        std::fs::write(&path, &policy.yaml)
            .with_context(|| format!("writing the document to {}", path.display()))?;
        if matches!(output, OutputFormat::Json) {
            println!("{}", serde_json::to_string_pretty(&policy)?);
        } else {
            println!(
                "{} rules for {} workloads written to {}",
                policy.rules,
                policy.workloads,
                path.display()
            );
        }
        return Ok(());
    }
    if matches!(output, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&policy)?);
        return Ok(());
    }
    print!("{}", policy.yaml);
    Ok(())
}

/// Write the rules segmenting the containers on the node's bridges.
///
/// Like the allow-list, the document is printed or written to a file and
/// never applied here, and every rule in it is in observe mode.
pub async fn cmd_learning_segmentation(
    client: &ApiClient,
    id: Option<String>,
    output_file: Option<PathBuf>,
    output: OutputFormat,
) -> Result<()> {
    let id = resolve_learning_id(client, id).await?;
    let document = client.learning_segmentation(&id).await?;
    if matches!(output, OutputFormat::Json) {
        if let Some(path) = &output_file {
            std::fs::write(path, &document.yaml)
                .with_context(|| format!("writing the document to {}", path.display()))?;
        }
        println!("{}", serde_json::to_string_pretty(&document)?);
        return Ok(());
    }
    let Some(path) = output_file else {
        print!("{}", document.yaml);
        return Ok(());
    };
    std::fs::write(&path, &document.yaml)
        .with_context(|| format!("writing the document to {}", path.display()))?;
    println!(
        "{} rules for {} containers on {} bridges written to {}",
        document.rules,
        document.containers,
        document.bridges,
        path.display()
    );
    for name in &document.unlearned {
        println!("not seen by the window, left without a rule: {name}");
    }
    for name in &document.unnamed {
        println!("seen under a name no rule can select: {name}");
    }
    Ok(())
}

/// What a window saw, one edge per line, then the addresses each workload
/// dialled from: the raw material a fleet-wide reading groups into segments.
pub async fn cmd_learning_edges(
    client: &ApiClient,
    id: Option<String>,
    output: OutputFormat,
) -> Result<()> {
    let id = resolve_learning_id(client, id).await?;
    let window = client.learning_edges(&id).await?;
    if matches!(output, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&window)?);
        return Ok(());
    }
    println!(
        "{} edges in window {} ({}s watched)",
        window.edges.len(),
        window.session.id,
        window.session.elapsed_secs
    );
    for edge in &window.edges {
        println!(
            "{}:{} -> {}:{}/{} seen {} times",
            edge.workload.kind,
            edge.workload.value,
            edge.destination,
            edge.port,
            edge.protocol,
            edge.observations
        );
    }
    for held in &window.addresses {
        println!(
            "{}:{} dials from {}",
            held.workload.kind,
            held.workload.value,
            held.addresses.join(", ")
        );
    }
    Ok(())
}

/// An id the caller did not give is the window that is still running.
///
/// Asking the agent rather than remembering locally is what makes the
/// command usable from a second terminal, and a node with no window open
/// is told so here rather than through a 404 naming an id nobody typed.
async fn resolve_learning_id(client: &ApiClient, id: Option<String>) -> Result<String> {
    if let Some(id) = id {
        return Ok(id);
    }
    let sessions = client.learning_sessions().await?;
    let running: Vec<&LearningSessionResponse> =
        sessions.iter().filter(|s| s.status == "running").collect();
    match running.as_slice() {
        [session] => Ok(session.id.clone()),
        [] => bail!("no learning window is open on this node; name one with its id"),
        _ => bail!("more than one window is open; name the one you mean with its id"),
    }
}

fn learning_scope(
    cgroup: Option<String>,
    exe: Vec<String>,
    unit: Vec<String>,
    container: Vec<String>,
) -> LearningScopeBody {
    if let Some(path) = cgroup {
        return LearningScopeBody::Cgroup { path };
    }
    let selectors: Vec<LearningSelector> = exe
        .into_iter()
        .map(|exe| LearningSelector {
            exe: Some(exe),
            ..LearningSelector::default()
        })
        .chain(unit.into_iter().map(|unit| LearningSelector {
            unit: Some(unit),
            ..LearningSelector::default()
        }))
        .chain(container.into_iter().map(|container| LearningSelector {
            container: Some(container),
            ..LearningSelector::default()
        }))
        .collect();
    if selectors.is_empty() {
        LearningScopeBody::Node
    } else {
        LearningScopeBody::Workloads { selectors }
    }
}

fn print_learning_session(session: &LearningSessionResponse, output: OutputFormat) -> Result<()> {
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(session)?);
        return Ok(());
    }

    println!("id:          {}", session.id);
    println!("status:      {}", session.status);
    println!("scope:       {}", session.scope_description);
    println!(
        "window:      {}s elapsed of {}s, {}s left",
        session.elapsed_secs, session.requested_duration_secs, session.remaining_secs
    );
    println!(
        "edges:       {} of {} ({} observations, {} unattributed, {} out of scope)",
        session.edges,
        session.capacity,
        session.observations,
        session.unattributed,
        session.out_of_scope
    );
    match session.secs_since_new_edge {
        Some(secs) => println!("last new:    {secs}s ago"),
        None => println!("last new:    nothing seen yet"),
    }
    if session.gap_secs > 0 {
        println!(
            "gap:         the agent was down for {}s of this window",
            session.gap_secs
        );
    } else if !session.continuous {
        println!("gap:         the agent did not run for all of this window");
    }
    if session.dropped_edges > 0 {
        println!(
            "dropped:     {} destinations refused, the window is full",
            session.dropped_edges
        );
    }
    Ok(())
}

pub async fn cmd_host_rules_list(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.host_rules().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    if resp.rules.is_empty() {
        println!("No host rule is loaded.");
        return Ok(());
    }
    let mut table = Table::new(&[
        ("RULE", Align::Left),
        ("SEVERITY", Align::Left),
        ("STATE", Align::Left),
        ("MODE", Align::Left),
        ("WOULD HAVE", Align::Right),
        ("THEN", Align::Left),
        ("INTENTS", Align::Left),
    ]);
    for rule in &resp.rules {
        let intents: Vec<&str> = rule.intents.iter().map(|i| i.name.as_str()).collect();
        let would_have = rule
            .shadow
            .as_ref()
            .map_or_else(|| "-".to_string(), |s| s.events.to_string());
        table.row(cells![
            rule.id,
            rule.severity,
            rule.state.replace('_', " "),
            rule.mode,
            would_have,
            rule.then.join(", "),
            intents.join(", "),
        ]);
    }
    table.print();
    println!(
        "{} rules, {} events matched, {} alerts lost to a full queue.",
        resp.rules.len(),
        resp.matched,
        resp.dropped
    );
    if resp.pending > 0 || resp.pending_refused > 0 {
        println!(
            "{} first steps waiting for their second, {} not held because the set was full.",
            resp.pending, resp.pending_refused
        );
    }
    if resp.counting > 0 || resp.counting_refused > 0 {
        println!(
            "{} counts running, {} events not counted because a bound was hit.",
            resp.counting, resp.counting_refused
        );
    }
    for exception in &resp.exceptions {
        let rules = if exception.rules.is_empty() {
            "every rule".to_string()
        } else {
            exception.rules.join(", ")
        };
        println!(
            "Exception {}: {rules} leave {} alone.",
            exception.id, exception.workload
        );
    }
    if resp.exempted > 0 {
        println!("{} matches left alone by an exception.", resp.exempted);
    }
    for rule in &resp.rules {
        if let Some(shadow) = rule.shadow.as_ref().filter(|s| s.events > 0) {
            let hits: Vec<String> = shadow
                .workloads
                .iter()
                .map(|w| format!("{} {}", w.workload.as_deref().unwrap_or("host"), w.events))
                .collect();
            println!(
                "  {} would have acted on: {}{}",
                rule.id,
                hits.join(", "),
                if shadow.unsampled > 0 {
                    format!(", {} more unnamed", shadow.unsampled)
                } else {
                    String::new()
                }
            );
        }
        for intent in &rule.intents {
            if let Some(reason) = &intent.reason {
                println!("  {} / {}: {reason}", rule.id, intent.name);
            }
        }
    }
    Ok(())
}

pub async fn cmd_host_rules_intents(client: &ApiClient, output: OutputFormat) -> Result<()> {
    let resp = client.host_intents().await?;

    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    let mut table = Table::new(&[
        ("INTENT", Align::Left),
        ("STATE", Align::Left),
        ("HOOK", Align::Left),
        ("FIELDS", Align::Left),
    ]);
    for intent in &resp.intents {
        let fields: Vec<&str> = intent.fields.iter().map(|f| f.name.as_str()).collect();
        table.row(cells![
            intent.name,
            intent.state.replace('_', " "),
            intent.hook,
            fields.join(", "),
        ]);
    }
    table.print();
    println!(
        "{} of {} intentions served on this host{}.",
        resp.applicable,
        resp.intents.len(),
        resp.kernel
            .as_deref()
            .map(|k| format!(", kernel {k}"))
            .unwrap_or_default()
    );
    for intent in resp.intents.iter().filter(|i| i.reason.is_some()) {
        if let Some(reason) = &intent.reason {
            println!("  {}: {reason}", intent.name);
        }
    }
    Ok(())
}

/// Say which rules naming a workload on another node are decided where the
/// connection leaves and nowhere else, with the reason, under the table.
fn print_source_only(rules: &[crate::api_client::WorkloadReachEntry]) {
    for rule in rules {
        if rule.decided_at.as_deref() == Some("source") {
            println!(
                "\nRule {} is decided only on the node a connection leaves: {}.",
                rule.rule,
                rule.source_only_reason
                    .as_deref()
                    .unwrap_or("the node it arrives at cannot read it")
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_round_trip_quantile_is_the_bound_of_the_bucket_crossing_it() {
        let mut buckets = vec![0; 16];
        buckets[4] = 98; // below 1.024 ms
        buckets[15] = 2; // above the last bound
        let rt = crate::api_client::RoundTripBody {
            buckets,
            first_bound_us: 64,
            sum_us: 0,
            count: 100,
        };
        assert_eq!(rtt_quantile_ms(&rt, 0.5), "1.02");
        assert_eq!(rtt_quantile_ms(&rt, 0.98), "1.02");
        assert_eq!(rtt_quantile_ms(&rt, 0.99), ">1048.58");
        let empty = crate::api_client::RoundTripBody {
            buckets: vec![0; 16],
            first_bound_us: 64,
            sum_us: 0,
            count: 0,
        };
        assert_eq!(rtt_quantile_ms(&empty, 0.5), "-");
    }

    #[test]
    fn the_certificate_cell_says_why_nothing_is_known_or_how_far_the_end_is() {
        let cert = |state: &str, not_after: Option<i64>| crate::api_client::CertificateBody {
            state: state.to_string(),
            not_before: None,
            not_after,
        };
        assert_eq!(
            certificate_cell(&cert("not_observable", None), 0),
            "not observable (TLS 1.3)"
        );
        assert_eq!(
            certificate_cell(&cert("not_captured", None), 0),
            "not captured"
        );
        assert_eq!(
            certificate_cell(&cert("read", Some(10 * 86_400)), 0),
            "expires in 10 days"
        );
        assert_eq!(
            certificate_cell(&cert("read", Some(0)), 3 * 86_400),
            "expired 3 days ago"
        );
    }

    #[test]
    fn the_clear_text_cell_names_its_protocols() {
        let mut counts = crate::api_client::PostureCountsBody {
            clear_text: 3,
            ..Default::default()
        };
        counts.shares.clear_text = 0.75;
        assert_eq!(clear_text_cell(&counts), "3 (75%)");
        counts.clear_text_protocols.insert("http".to_string(), 2);
        counts.clear_text_protocols.insert("ldap".to_string(), 1);
        assert_eq!(clear_text_cell(&counts), "3 (75%) http 2, ldap 1");
    }

    #[test]
    fn a_podman_runtime_says_whose_it_is_and_why_it_names_nothing() {
        let line = podman_runtime_line(&crate::api_client::PodmanRuntime {
            uid: Some(1000),
            socket: "/run/user/1000/podman/podman.sock".to_string(),
            reach: "refused".to_string(),
        });
        assert_eq!(
            line,
            "podman uid 1000: unnamed, the socket refused the agent \
             (/run/user/1000/podman/podman.sock)"
        );
        let root = podman_runtime_line(&crate::api_client::PodmanRuntime {
            uid: None,
            socket: "/run/podman/podman.sock".to_string(),
            reach: "reachable".to_string(),
        });
        assert!(root.starts_with("podman root: named"), "{root}");
    }

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
            kill_process: false,
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

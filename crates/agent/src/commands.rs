use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::api_client::{
    AlertResponse, ApiClient, ConnectionResponse, ConntrackEventFrame, IdsRuleResponse,
    IpsRuleResponse, LearningScopeBody, LearningSelector, LearningSessionResponse,
    NetpolReplayBody, NetpolReplayResponse, StartLearningBody, StreamOpenError,
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

    if !listing.enforcing {
        println!("\nNo rule in force refuses: every one of them only counts.");
    }
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
        let procfs = if coverage.host_proc {
            "host procfs"
        } else {
            "own procfs"
        };
        println!(
            "  Containers {} ({procfs}), ids {}, docker {}, kubernetes {}",
            coverage.proc_root,
            if coverage.resolver { "yes" } else { "no" },
            enricher_state(&coverage.docker),
            enricher_state(&coverage.kubernetes),
        );
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

    println!("\nWorkload firewall");
    println!("  Attached:   {}", yes_no(resp.workload_firewall.attached));
    println!("  Cgroup:     {}", resp.workload_firewall.cgroup);
    println!("  Brokered:   {}", yes_no(resp.workload_firewall.brokered));
    if !resp.workload_firewall.hooks.is_empty() {
        println!("  Hooks:      {}", resp.workload_firewall.hooks.join(", "));
    }
    if let Some(reason) = &resp.workload_firewall.reason {
        println!("  Reason:     {reason}");
    }

    print_process_signal(&resp.process_signal);
    print_quarantine(&resp.quarantine);

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

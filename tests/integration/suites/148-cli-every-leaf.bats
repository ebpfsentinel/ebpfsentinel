#!/usr/bin/env bats
# 148-cli-every-leaf.bats - every command of the agent's own command line,
# run the way an operator runs it beside the agent, with its answer read.
#
# The REST suites read the routes; this one reads the command line on top of
# them, so a command that parses the wrong body, prints the wrong field or
# never reaches its route fails here even while the route itself is right.
# Every command runs with `-o json` and the answer is read with jq. A command
# whose answer depends on what the host offers (conntrack, the workload
# firewall, the Kubernetes inventory) accepts the answer or the refusal that
# names the missing piece, never a bare non-zero exit.

load '../lib/helpers'

setup_file() {
    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export AGENT_BIN="${AGENT_BIN:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
    export DATA_DIR="/tmp/ebpfsentinel-test-data-$$"
    mkdir -p "$DATA_DIR"
    export EBPFSENTINEL_PORT="${AGENT_HTTP_PORT}"
    export EBPFSENTINEL_HOST=127.0.0.1

    export PREPARED_CONFIG="/tmp/ebpfsentinel-test-config-$$.yaml"
    prepare_full_config "$PREPARED_CONFIG"

    # Started, stopped by signal and started again on the same data
    # directory: the second start records the first stop as an alert, which
    # gives the alert commands a real one to show, triage and mark.
    start_agent "$PREPARED_CONFIG"
    stop_agent
    start_agent "$PREPARED_CONFIG"
}

teardown_file() {
    stop_agent 2>/dev/null || true
    rm -rf "$DATA_DIR"
    rm -f "$PREPARED_CONFIG"
}

# cli <binary> <words...> - run one command with JSON output; stdout lands in
# CLI_OUT, stderr in CLI_ERR, the exit status in CLI_RC.
cli() {
    local err
    err="$(mktemp)"
    CLI_RC=0
    CLI_OUT="$("$@" -o json 2>"$err")" || CLI_RC=$?
    CLI_ERR="$(cat "$err")"
    rm -f "$err"
}

# ok - the last command exited zero.
ok() {
    [ "$CLI_RC" -eq 0 ] || {
        echo "exit ${CLI_RC}: ${CLI_ERR}" >&2
        return 1
    }
}

# reads <jq filter> - the last command's stdout satisfies the filter.
reads() {
    echo "$CLI_OUT" | jq -e "$1" >/dev/null || {
        echo "filter '$1' failed on: ${CLI_OUT}" >&2
        return 1
    }
}

# refused <text> - the last command exited non-zero and said why.
refused() {
    [ "$CLI_RC" -ne 0 ] && grep -qF -- "$1" <<<"$CLI_ERR" || {
        echo "expected a refusal naming '$1', got exit ${CLI_RC}: ${CLI_ERR} ${CLI_OUT}" >&2
        return 1
    }
}

# answers_or_refused <jq filter> <text> - a host-dependent command either
# answers with the shape or names the piece the host lacks.
answers_or_refused() {
    if [ "$CLI_RC" -eq 0 ]; then
        reads "$1"
    else
        refused "$2"
    fi
}

first_alert_id() {
    "$AGENT_BIN" alerts list -o json | jq -r '.alerts[0].id // empty'
}

# ── Identity and state ─────────────────────────────────────────────

@test "version names the binary" {
    run "$AGENT_BIN" version
    [ "$status" -eq 0 ]
    [[ "$output" == ebpfsentinel-agent\ * ]]
}

@test "status reports the agent block" {
    cli "$AGENT_BIN" status
    ok
    reads '.agent | type == "object"'
}

@test "score carries its factors and details" {
    cli "$AGENT_BIN" score
    ok
    reads '(.details.alert_count | type == "object") and has("factors")'
}

@test "metrics prints the Prometheus exposition" {
    cli "$AGENT_BIN" metrics
    ok
    grep -q '^# TYPE ebpfsentinel_rules_loaded gauge' <<<"$CLI_OUT"
}

@test "config show returns the running configuration" {
    cli "$AGENT_BIN" config show
    ok
    reads '(.agent | type == "object") and .firewall != null'
}

@test "config set writes one section and reloads" {
    local doc="${DATA_DIR}/ids-section.yaml"
    printf 'ids:\n  enabled: true\n  mode: alert\n' >"$doc"
    cli "$AGENT_BIN" config set ids --file "$doc"
    ok
    reads '.status == "ok"'
    cli "$AGENT_BIN" config show
    reads '.ids.enabled == true and .ids.mode == "alert"'
}

@test "config set refuses a document not rooted at the section" {
    local doc="${DATA_DIR}/ids-unrooted.yaml"
    printf 'enabled: true\n' >"$doc"
    cli "$AGENT_BIN" config set ids --file "$doc"
    refused "SECTION_MISSING"
}

@test "config reload answers ok" {
    cli "$AGENT_BIN" config reload
    ok
    reads '.status == "ok"'
}

# ── Alerts and audit ───────────────────────────────────────────────

@test "alerts list carries the stop recorded at the last start" {
    cli "$AGENT_BIN" alerts list
    ok
    reads 'any(.alerts[]; .rule_id == "agent-stopped-by-signal" and .component == "agent_lifecycle")'
}

@test "alerts stats counts what alerts list holds" {
    cli "$AGENT_BIN" alerts stats
    ok
    reads '.analyzed >= 1 and .by_component.agent_lifecycle >= 1'
}

@test "alerts show returns the one alert named" {
    local id
    id="$(first_alert_id)"
    [ -n "$id" ]
    cli "$AGENT_BIN" alerts show "$id"
    ok
    echo "$CLI_OUT" | jq -e --arg id "$id" '.id == $id and (.severity | type == "string")' >/dev/null
}

@test "alerts triage moves the alert to acknowledged" {
    local id
    id="$(first_alert_id)"
    cli "$AGENT_BIN" alerts triage "$id" --status acknowledged --note cli-suite
    ok
    echo "$CLI_OUT" | jq -e --arg id "$id" '.alert_id == $id and .status == "acknowledged"' >/dev/null
}

@test "alerts triage with nothing to change is refused" {
    cli "$AGENT_BIN" alerts triage "$(first_alert_id)"
    refused "INVALID_TRIAGE"
}

@test "alerts mark-fp marks the alert" {
    local id
    id="$(first_alert_id)"
    cli "$AGENT_BIN" alerts mark-fp "$id"
    ok
    echo "$CLI_OUT" | jq -e --arg id "$id" '.alert_id == $id and .marked == true' >/dev/null
}

@test "alerts mark-fp on an unknown alert is refused" {
    cli "$AGENT_BIN" alerts mark-fp no-such-alert
    refused "ALERT_NOT_FOUND"
}

@test "audit logs pages the trail" {
    cli "$AGENT_BIN" audit logs
    ok
    reads '(.entries | type == "array") and (.total | type == "number") and .limit > 0'
}

@test "audit history names the rule asked for" {
    cli "$AGENT_BIN" audit history fw-test-001
    ok
    reads '.rule_id == "fw-test-001" and (.entries | type == "array")'
}

# ── Firewall ───────────────────────────────────────────────────────

@test "firewall list carries the fixture rule" {
    cli "$AGENT_BIN" firewall list
    ok
    reads 'any(.[]; .id == "fw-test-001")'
}

@test "firewall add then delete round trips a rule" {
    cli "$AGENT_BIN" firewall add --json '{"id":"cli-fw","priority":500,"action":"deny","protocol":"tcp","dst_port":9998,"scope":"global","enabled":true}'
    ok
    reads '.id == "cli-fw" and .action == "deny" and .dst_port == "9998"'
    cli "$AGENT_BIN" firewall delete cli-fw
    ok
    cli "$AGENT_BIN" firewall list
    reads 'all(.[]; .id != "cli-fw")'
}

@test "firewall shadow reports its counting window" {
    cli "$AGENT_BIN" firewall shadow
    ok
    reads '(.counting_since_ns | type == "number") and (.rules | type == "array")'
}

@test "firewall workload answers or names the missing program" {
    cli "$AGENT_BIN" firewall workload
    answers_or_refused 'type == "object" or type == "array"' "workload firewall is not loaded"
}

@test "firewall fqdn answers or names the missing program" {
    cli "$AGENT_BIN" firewall fqdn
    answers_or_refused 'type == "object" or type == "array"' "workload firewall is not loaded"
}

@test "firewall labels answers or names the missing program" {
    cli "$AGENT_BIN" firewall labels
    answers_or_refused 'type == "object" or type == "array"' "workload firewall is not loaded"
}

@test "firewall reach answers for an executable or names the missing program" {
    cli "$AGENT_BIN" firewall reach --exe /usr/bin/curl
    answers_or_refused 'type == "object"' "workload firewall is not loaded"
}

@test "firewall reach without a workload asks for one" {
    cli "$AGENT_BIN" firewall reach
    refused "name the workload"
}

# ── L7, rate limit, IPS, DDoS ──────────────────────────────────────

@test "l7 add, list and delete round trip a rule" {
    cli "$AGENT_BIN" l7 add --json '{"id":"cli-l7","priority":100,"action":"deny","protocol":"http","path":"/admin","enabled":true}'
    ok
    reads '.id == "cli-l7" and .matcher.path_pattern == "/admin"'
    cli "$AGENT_BIN" l7 list
    reads 'any(.[]; .id == "cli-l7")'
    cli "$AGENT_BIN" l7 delete cli-l7
    ok
    cli "$AGENT_BIN" l7 list
    reads 'all(.[]; .id != "cli-l7")'
}

@test "ratelimit add, list and delete round trip a rule" {
    cli "$AGENT_BIN" ratelimit add --json '{"id":"cli-rl","src_ip":"203.0.113.10/32","rate":100,"burst":200,"action":"drop","algorithm":"token_bucket"}'
    ok
    reads '.id == "cli-rl" and .src_ip == "203.0.113.10/32" and .rate == 100'
    cli "$AGENT_BIN" ratelimit list
    reads 'any(.[]; .id == "cli-rl")'
    cli "$AGENT_BIN" ratelimit delete cli-rl
    ok
    cli "$AGENT_BIN" ratelimit list
    reads 'all(.[]; .id != "cli-rl")'
}

@test "ips list and domain-blocks answer arrays" {
    cli "$AGENT_BIN" ips list
    ok
    reads 'type == "array"'
    cli "$AGENT_BIN" ips domain-blocks
    ok
    reads 'type == "array"'
}

@test "ips blacklist add then delete round trips an address" {
    cli "$AGENT_BIN" ips blacklist add 203.0.113.77 --reason cli-suite --ttl-secs 60
    ok
    reads '.ip == "203.0.113.77" and .reason == "cli-suite" and .ttl_remaining_secs <= 60'
    cli "$AGENT_BIN" ips blacklist delete 203.0.113.77
    ok
    reads '.ip == "203.0.113.77" and .removed == true'
}

@test "ips set-mode on an unknown rule is refused" {
    cli "$AGENT_BIN" ips set-mode no-such-rule --mode block
    refused "RULE_NOT_FOUND"
}

@test "ddos status counts the fixture policy" {
    cli "$AGENT_BIN" ddos status
    ok
    reads '.enabled == true and .policy_count >= 1'
}

@test "ddos policies, attacks and history answer" {
    cli "$AGENT_BIN" ddos policies
    ok
    reads 'any(.[]; .id == "ddos-test-syn" and .attack_type == "syn_flood")'
    cli "$AGENT_BIN" ddos attacks
    ok
    reads 'type == "array"'
    cli "$AGENT_BIN" ddos history
    ok
    reads 'type == "array"'
}

@test "ddos add then delete round trips a policy" {
    cli "$AGENT_BIN" ddos add --json '{"id":"cli-ddos","attack_type":"icmp_flood","detection_threshold_pps":5000,"mitigation_action":"block","auto_block_duration_secs":120,"enabled":true}'
    ok
    reads '.id == "cli-ddos" and .detection_threshold_pps == 5000'
    cli "$AGENT_BIN" ddos delete cli-ddos
    ok
    cli "$AGENT_BIN" ddos policies
    reads 'all(.[]; .id != "cli-ddos")'
}

# ── Detection engines ──────────────────────────────────────────────

@test "ids status, rules and suricata answer" {
    cli "$AGENT_BIN" ids status
    ok
    reads '(.enabled | type == "boolean") and (.rule_count | type == "number")'
    cli "$AGENT_BIN" ids rules
    ok
    reads 'type == "array"'
    cli "$AGENT_BIN" ids suricata
    ok
    reads '.rulesets | type == "array"'
}

@test "ids suricata-check reads a file and counts what it refused" {
    local rules="${DATA_DIR}/cli.rules"
    printf 'not a rule\n' >"$rules"
    cli "$AGENT_BIN" ids suricata-check "$rules"
    ok
    reads '.rulesets[0].total == 1 and .rulesets[0].compiled == 0'
}

@test "dlp status, patterns and scope answer" {
    cli "$AGENT_BIN" dlp status
    ok
    reads '.pattern_count > 0'
    cli "$AGENT_BIN" dlp patterns
    ok
    reads 'any(.[]; .id == "dlp-pci-visa")'
    cli "$AGENT_BIN" dlp scope
    ok
    reads '(.mode | type == "string") and (.in_scope | type == "array")'
}

@test "threatintel status, iocs and urls answer" {
    cli "$AGENT_BIN" threatintel status
    ok
    reads '(.ioc_count | type == "number") and (.feed_count | type == "number")'
    cli "$AGENT_BIN" threatintel iocs
    ok
    reads 'type == "array"'
    cli "$AGENT_BIN" threatintel urls
    ok
    reads 'type == "array"'
}

@test "threatintel feeds refresh answers or says feeds are off" {
    cli "$AGENT_BIN" threatintel feeds refresh
    answers_or_refused 'type == "object"' "feeds are not enabled"
}

@test "mitre coverage lists techniques" {
    cli "$AGENT_BIN" mitre coverage
    ok
    reads '.total_techniques > 0 and (.techniques | length) == .total_techniques'
}

@test "fingerprints summary reports the cache bounds" {
    cli "$AGENT_BIN" fingerprints summary
    ok
    reads '.max_size > 0 and .ttl_seconds > 0'
}

@test "responses list and revoke of an unknown action" {
    cli "$AGENT_BIN" responses list
    ok
    reads '(.actions | type == "array") and (.active_count | type == "number")'
    cli "$AGENT_BIN" responses revoke no-such-action
    refused "RESPONSE_NOT_FOUND"
}

# ── DNS and domains ────────────────────────────────────────────────

@test "dns status, stats, cache and blocklist answer" {
    cli "$AGENT_BIN" dns status
    ok
    reads '.enabled | type == "boolean"'
    cli "$AGENT_BIN" dns stats
    ok
    reads '(.hit_count | type == "number") and (.top_queried | type == "array")'
    cli "$AGENT_BIN" dns cache
    ok
    reads '(.entries | type == "array") and .page_size > 0'
    cli "$AGENT_BIN" dns blocklist
    ok
    reads 'type == "array"'
}

@test "dns flush answers the count flushed" {
    cli "$AGENT_BIN" dns flush
    ok
    reads '.flushed_entries | type == "number"'
}

@test "domains block, reputation and unblock round trip" {
    cli "$AGENT_BIN" domains block cli-suite.example
    ok
    reads '.domain == "cli-suite.example" and .added == true'
    cli "$AGENT_BIN" dns blocklist
    reads 'any(.[]; .pattern == "cli-suite.example")'
    cli "$AGENT_BIN" domains reputation
    ok
    reads '.entries | type == "array"'
    cli "$AGENT_BIN" domains unblock cli-suite.example
    ok
    reads '.removed == true'
    cli "$AGENT_BIN" dns blocklist
    reads 'all(.[]; .pattern != "cli-suite.example")'
}

# ── Aliases, NAT, routing, zones ───────────────────────────────────

@test "aliases status counts the fixture aliases" {
    cli "$AGENT_BIN" aliases status
    ok
    reads '.alias_count >= 1'
}

@test "aliases set-content replaces an external alias" {
    cli "$AGENT_BIN" aliases set-content it-alias-external --json '{"ips":["10.98.0.0/24"]}'
    ok
    reads '.alias == "it-alias-external" and .ips_loaded == 1 and .status == "ok"'
}

@test "nat status and rules answer" {
    cli "$AGENT_BIN" nat status
    ok
    reads '.rule_count | type == "number"'
    cli "$AGENT_BIN" nat rules
    ok
    reads 'type == "array"'
}

@test "nat nptv6 create then delete round trips a rule" {
    cli "$AGENT_BIN" nat nptv6 create --id cli-npt --internal-prefix fd00:1:: --external-prefix 2001:db8:1:: --prefix-len 48
    ok
    reads '.id == "cli-npt" and .internal_prefix == "fd00:1::" and .prefix_len == 48'
    cli "$AGENT_BIN" nat nptv6 delete cli-npt
    ok
    cli "$AGENT_BIN" nat nptv6 delete cli-npt
    refused "RULE_NOT_FOUND"
}

@test "routing gateway add, list and delete round trip" {
    cli "$AGENT_BIN" routing add-gateway --json '{"name":"cli-gw","ip":"192.0.2.1"}'
    ok
    reads '.name == "cli-gw" and .gateway_ip == "192.0.2.1"'
    local id
    id="$(echo "$CLI_OUT" | jq -r '.id')"
    cli "$AGENT_BIN" routing gateways
    ok
    reads 'any(.[]; .name == "cli-gw")'
    cli "$AGENT_BIN" routing status
    ok
    reads '.gateway_count >= 1'
    cli "$AGENT_BIN" routing routes
    ok
    reads 'type == "array"'
    cli "$AGENT_BIN" routing delete-gateway "$id"
    ok
    cli "$AGENT_BIN" routing gateways
    reads 'all(.[]; .name != "cli-gw")'
}

@test "zones add, add-policy and their deletes round trip" {
    cli "$AGENT_BIN" zones add --json '{"name":"cli-zone-a","interfaces":["lo"]}'
    ok
    reads '.id == "cli-zone-a" and .interfaces == ["lo"]'
    cli "$AGENT_BIN" zones add --json '{"name":"cli-zone-b","interfaces":["cli-dummy0"]}'
    ok
    cli "$AGENT_BIN" zones add-policy --json '{"source_zone":"cli-zone-a","dest_zone":"cli-zone-b","action":"deny"}'
    ok
    reads '.from == "cli-zone-a" and .to == "cli-zone-b" and .action == "deny"'
    local pid
    pid="$(echo "$CLI_OUT" | jq -r '.id')"
    cli "$AGENT_BIN" zones policies
    reads 'any(.[]; .from == "cli-zone-a")'
    cli "$AGENT_BIN" zones status
    ok
    reads '.zone_count >= 2 and .policy_count >= 1'
    cli "$AGENT_BIN" zones delete-policy "$pid"
    ok
    cli "$AGENT_BIN" zones delete cli-zone-a
    ok
    cli "$AGENT_BIN" zones delete cli-zone-b
    ok
    cli "$AGENT_BIN" zones list
    reads 'all(.[]; .id != "cli-zone-a" and .id != "cli-zone-b")'
}

@test "zones add without an interface is refused" {
    cli "$AGENT_BIN" zones add --json '{"name":"cli-zone-empty"}'
    refused "must have at least one interface"
}

# ── Load balancer and QoS ──────────────────────────────────────────

@test "lb add, service, services and delete round trip" {
    cli "$AGENT_BIN" lb add --json '{"id":"cli-lb","name":"web-svc","protocol":"tcp","listen_port":8088,"algorithm":"round_robin","backends":[{"id":"be-1","addr":"10.0.0.1","port":8081,"weight":1}]}'
    ok
    reads '.id == "cli-lb" and .backend_count == 1'
    cli "$AGENT_BIN" lb service cli-lb
    ok
    reads '.id == "cli-lb" and .backends[0].addr == "10.0.0.1"'
    cli "$AGENT_BIN" lb services
    reads 'any(.[]; .id == "cli-lb")'
    cli "$AGENT_BIN" lb status
    ok
    reads '.service_count >= 1'
    cli "$AGENT_BIN" lb delete cli-lb
    ok
    cli "$AGENT_BIN" lb services
    reads 'all(.[]; .id != "cli-lb")'
}

@test "lb vips, bgp and announce answer" {
    cli "$AGENT_BIN" lb vips
    ok
    reads '(.role | type == "string") and (.vips | type == "array")'
    cli "$AGENT_BIN" lb bgp
    ok
    reads '.sessions | type == "array"'
    cli "$AGENT_BIN" lb announce --json '{"role":"disabled","interface":"","vips":[]}'
    ok
    reads '.role == "disabled" and .is_speaker == false'
}

@test "lb grant off an elected role is refused with the role named" {
    cli "$AGENT_BIN" lb grant 30
    refused "speaker grants apply to role elected"
}

@test "qos pipe, queue and classifier round trip" {
    cli "$AGENT_BIN" qos add-pipe --json '{"id":"cli-pipe","rate_bps":1000000}'
    ok
    reads '.id == "cli-pipe" and .rate_bps == 1000000'
    cli "$AGENT_BIN" qos add-queue --json '{"id":"cli-q","pipe_id":"cli-pipe","weight":10}'
    ok
    reads '.pipe_id == "cli-pipe"'
    cli "$AGENT_BIN" qos add-classifier --json '{"id":"cli-cls","queue_id":"cli-q","priority":10}'
    ok
    reads '.queue_id == "cli-q" and .priority == 10'
    cli "$AGENT_BIN" qos pipes
    reads 'any(.[]; .id == "cli-pipe")'
    cli "$AGENT_BIN" qos queues
    reads 'any(.[]; .id == "cli-q")'
    cli "$AGENT_BIN" qos classifiers
    reads 'any(.[]; .id == "cli-cls")'
    cli "$AGENT_BIN" qos status
    ok
    reads '.pipe_count >= 1 and .queue_count >= 1 and .classifier_count >= 1'
    cli "$AGENT_BIN" qos delete-classifier cli-cls
    ok
    cli "$AGENT_BIN" qos delete-queue cli-q
    ok
    cli "$AGENT_BIN" qos delete-pipe cli-pipe
    ok
    cli "$AGENT_BIN" qos pipes
    reads 'all(.[]; .id != "cli-pipe")'
}

@test "qos shaping lists the interfaces it read" {
    cli "$AGENT_BIN" qos shaping
    ok
    reads '(.supported | type == "boolean") and any(.interfaces[]; .name == "lo")'
}

# ── Connections and flows ──────────────────────────────────────────

@test "conntrack status counts connections" {
    cli "$AGENT_BIN" conntrack status
    ok
    reads '(.connection_count | type == "number") and .max_connections > 0'
}

@test "conntrack list answers or names the table it could not read" {
    cli "$AGENT_BIN" conntrack list
    answers_or_refused 'type == "array" or type == "object"' "conntrack query failed"
}

@test "conntrack flush answers or names the table it could not flush" {
    cli "$AGENT_BIN" conntrack flush
    answers_or_refused 'type == "object"' "conntrack flush failed"
}

@test "flows services reads the service graph window" {
    cli "$AGENT_BIN" flows services
    ok
    reads '.minutes > 0 and (.edges | type == "array")'
}

@test "flows export answers or says export is off" {
    cli "$AGENT_BIN" flows export
    answers_or_refused 'type == "object"' "Flow export not enabled"
}

@test "capture list answers and stop of an unknown capture is refused" {
    cli "$AGENT_BIN" capture list
    ok
    reads '.captures | type == "array"'
    cli "$AGENT_BIN" capture stop no-such-capture
    refused "CAPTURE_NOT_FOUND"
}

@test "geoip status answers and lookup names a missing database" {
    cli "$AGENT_BIN" geoip status
    ok
    reads '(.enabled | type == "boolean") and (.ready | type == "boolean")'
    cli "$AGENT_BIN" geoip lookup 8.8.8.8
    answers_or_refused 'type == "object"' "GeoIP lookup not available"
}

@test "top answers or names the table it could not read" {
    run timeout 10 "$AGENT_BIN" top -o json
    if [ "$status" -eq 0 ]; then
        echo "$output" | jq -e 'type == "object" or type == "array"' >/dev/null
    else
        [[ "$output" == *"conntrack query failed"* ]]
    fi
}

@test "watch opens the live alert stream" {
    run timeout 3 "$AGENT_BIN" watch -o json
    [[ "$output" == *"Watching alerts - live stream"* ]]
}

@test "conntrack watch opens the event stream or says it polls" {
    run timeout 3 "$AGENT_BIN" conntrack watch -o json
    [[ "$output" == *"Watching conntrack events"* ]]
}

# ── Learning ───────────────────────────────────────────────────────

@test "learning start, edges, policy, segmentation and stop on one window" {
    cli "$AGENT_BIN" learning start --duration 60
    ok
    reads '.status == "running" and .requested_duration_secs == 60'
    local id
    id="$(echo "$CLI_OUT" | jq -r '.id')"
    cli "$AGENT_BIN" learning edges
    ok
    echo "$CLI_OUT" | jq -e --arg id "$id" '.session.id == $id' >/dev/null
    cli "$AGENT_BIN" learning policy
    ok
    echo "$CLI_OUT" | jq -e --arg id "$id" '.session.id == $id' >/dev/null
    # Segmentation reads the open window's edges through the Docker source,
    # so it answers or names the source this node has switched off.
    cli "$AGENT_BIN" learning segmentation
    answers_or_refused 'type == "object"' "container.docker.enabled is off"
    cli "$AGENT_BIN" learning stop
    ok
    echo "$CLI_OUT" | jq -e --arg id "$id" '.id == $id and .status == "stopped"' >/dev/null
}

@test "learning edges with no open window says so" {
    cli "$AGENT_BIN" learning edges
    refused "no learning window is open"
}

# ── Host and eBPF ──────────────────────────────────────────────────

@test "ebpf status lists the programs" {
    cli "$AGENT_BIN" ebpf status
    ok
    reads '(.programs | length) > 0 and all(.programs[]; (.name | type == "string") and (.loaded | type == "boolean"))'
}

@test "ebpf kernel-features reports the load mode" {
    cli "$AGENT_BIN" ebpf kernel-features
    ok
    reads '(.probed | type == "boolean") and (.load_mode | type == "string")'
}

@test "ebpf host-check names the LSM modules" {
    cli "$AGENT_BIN" ebpf host-check
    ok
    reads '(.active | type == "boolean") and (.modules | type == "array")'
}

@test "ebpf drops, uprobes and raw-sockets answer" {
    cli "$AGENT_BIN" ebpf drops
    ok
    reads '(.counting | type == "boolean") and (.drops | type == "array")'
    cli "$AGENT_BIN" ebpf uprobes
    ok
    reads '.probes | type == "array"'
    cli "$AGENT_BIN" ebpf raw-sockets
    ok
    reads '(.reading | type == "boolean") and (.sockets | type == "array")'
}

@test "ebpf foreign-programs, hidden-ports and hidden-processes answer" {
    cli "$AGENT_BIN" ebpf foreign-programs
    ok
    reads '(.reading | type == "boolean") and (.programs | type == "array")'
    cli "$AGENT_BIN" ebpf hidden-ports
    ok
    reads '.probed_ports > 0 and (.counts | type == "object")'
    cli "$AGENT_BIN" ebpf hidden-processes
    ok
    reads '.pids_per_second > 0 and (.counts | type == "object")'
}

@test "ebpf guests answers or names the missing link watcher" {
    cli "$AGENT_BIN" ebpf guests
    answers_or_refused 'type == "object"' "link watcher does not run"
}

@test "ebpf coverage answers or names the missing pod inventory" {
    cli "$AGENT_BIN" ebpf coverage
    answers_or_refused 'type == "object"' "no pod inventory on this node"
}

@test "exposure listeners answers" {
    cli "$AGENT_BIN" exposure listeners
    ok
    reads '(.reading | type == "boolean") and (.listeners | type == "array")'
}

@test "host-rules list, intents, mass-encryption and write-refusal answer" {
    cli "$AGENT_BIN" host-rules list
    ok
    reads '(.rules | type == "array") and (.matched | type == "number")'
    cli "$AGENT_BIN" host-rules intents
    ok
    reads '(.kernel | type == "string") and (.intents | length) > 0'
    cli "$AGENT_BIN" host-rules mass-encryption
    ok
    reads '(.enabled | type == "boolean") and (.shadow.events | type == "number")'
    cli "$AGENT_BIN" host-rules write-refusal
    ok
    reads '(.enabled | type == "boolean") and (.recent | type == "array")'
}

@test "tls status, posture, handshakes and links answer" {
    cli "$AGENT_BIN" tls status
    ok
    reads '(.tls | type == "boolean") and (.post_quantum | type == "boolean")'
    cli "$AGENT_BIN" tls posture
    ok
    reads '.totals.connections | type == "number"'
    cli "$AGENT_BIN" tls handshakes
    ok
    reads '.capacity > 0 and (.handshakes | type == "array")'
    cli "$AGENT_BIN" tls links
    ok
    reads '(.outbound_mode | type == "string") and any(.links[]; .link == "outbound")'
}

# ── Stop, last: the agent does not come back ───────────────────────

@test "stop ends the agent and records why" {
    run "$AGENT_BIN" stop --reason cli-suite -o json
    [ "$status" -eq 0 ]
    local waited=0
    while kill -0 "$AGENT_PID" 2>/dev/null && [ "$waited" -lt 30 ]; do
        sleep 0.5
        waited=$((waited + 1))
    done
    ! kill -0 "$AGENT_PID" 2>/dev/null
}

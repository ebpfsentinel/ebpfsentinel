# Tool-coverage action plan — wire every provisioned tool into a real test

Goal: every tool the provisioners install is exercised by at least one bats
assertion against the agent data plane, and every tool a suite needs is
provisioned. No installed-but-unused tools; no gated-on-a-missing-tool suites.

Lane legend: local = bats netns on agent VM · 2VM = attacker NIC → agent ·
3VM = transit · k8s = minikube · perf = 2VM real-NIC.

## WS1 — provisioning gaps (make gated tools present)

| # | Fix | File | Check |
|---|---|---|---|
| 1.1 | install Go toolchain (pinned) | setup-attacker.sh | `go version` |
| 1.2 | openssl 3.5 (done) verify | setup-agent.sh | `list -kem-algorithms | grep X25519MLKEM768` |
| 1.3 | MHDDoS bootstrap hardening (clone pinned if submodule empty; fail loud) | setup-attacker.sh | `/opt/MHDDoS/start.py` present |
| 1.4 | kubectl/minikube pin + retry | Vagrantfile | `kubectl version --client` |
| 1.5 | extend attacker_tools_check to Go + every tk tool | attacker_tools_check.sh | 0 missing |

## WS2 — wire every dead-provisioned tool to a real assertion

| Tool | Target suite | Assertion |
|---|---|---|
| swaks | 56 | real SMTP EHLO → l7 audit (rule l7-smtp-ehlo-log) |
| lftp | 56 | real FTP PORT → l7 deny (l7-ftp-port-deny) |
| smbclient | 56 | real SMB1 negotiate → l7 deny (l7-smb-smb1-deny) |
| vegeta | 52 | HTTP load drives hot-reload-under-load (alt to curl burst) |
| k6 | 52 | scripted HTTP load sustains during rule swap |
| wrk | 52 | already fallback — assert it drives when present |
| nuclei | 12 / 29 | HTTP attack templates trip IDS/L7 patterns |
| cloudflared | 45 | DoH client → DoH detection alert |
| dnscrypt-proxy | 45 | DoT/DoH client → encrypted-DNS detection |
| hyenae-ng | 40 / 23 | crafted L2/L3 flood → scrub/ddos counters |
| nping | 22 / 42 | crafted TCP flags → ratelimit/reject path |
| t50 | 22 | multi-proto flood → ratelimit drops |
| dnsperf | 19 / 45 | sustained DNS load → dns inspected counter |
| ncrack | 59 | alt SSH brute → T1110 IDS + IPS blacklist |
| sshpass | 59 | non-interactive auth for negative-path assert |
| stress-ng | perf/01 | CPU-noise sensitivity guard on baseline spread |
| mitmproxy | 60 | TLS MITM → DLP alert on intercepted flow |

## WS3 — harden defensive skips now that tools are guaranteed

Convert `env_skip "<tool> not installed/available"` for provisioned tools to
FAIL under EBPFSENTINEL_STRICT_SKIPS=1 (reclassify masking, or require_tool
hard). Register new reasons; audit-skips.sh RC=0.

## WS4 — live validation matrix (needs booted VMs)

Run each lane with EBPFSENTINEL_STRICT_SKIPS=1; exit criterion = every suite
PASS or legitimately env-skipped (capability truly absent from the lane), zero
masking skip. Fix scripts, never hosts.

## Execution order

Phase A (no VM): WS1 + WS2 + WS3, gate after each
(bash -n, bats --count, audit-skips/coverage RC=0, and for Rust fmt/clippy/test/audit/deny).
Phase B (VM): WS4 lane by lane.

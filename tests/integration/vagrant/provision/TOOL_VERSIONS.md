# Attacker VM — Pinned Tool Versions

Reproducibility matters for the Wave-2 attack suites: a `vegeta -rate 10000`
on tool version N may emit a different burst profile from version N+1 and
quietly invalidate a regression assertion. Every tool the
`setup-attacker.sh` provisioner installs is pinned here. The
`attacker_tools_check.sh` script verifies every pin at the end of
provisioning and on demand.

## apt packages (Ubuntu 24.04 LTS — agent VM base box)

| Tool | apt package | Pinned series | Verified via |
|---|---|---|---|
| slowhttptest | `slowhttptest` | 1.9.0+ | `slowhttptest -h` matches "slowhttptest, version 1.9" |
| nping | `nmap` | 7.94+ | `nping --version` contains "Nping 0.7.9" |
| t50 | `t50` | 5.8.7+ | `t50 -v` contains "T50 Experimental Mixed Packet Injector" |
| wrk | `wrk` | 4.2.0+ | `wrk -v` contains "wrk 4." |
| dnsperf | `dnsperf` | 2.11+ | `dnsperf -h` runs without error |
| hydra | `hydra` | 9.5+ | `hydra -h` contains "Hydra v9." |
| ncrack | `ncrack` | 0.7+ | `ncrack -V` contains "Ncrack 0.7" |
| sshpass | `sshpass` | 1.09+ | `sshpass -V` |
| tcpdump | `tcpdump` | 4.99+ | `tcpdump --version` |

The series gates are loose because Ubuntu LTS pins these inside its own
repos; tightening would force PPAs and add CI fragility. The check script
verifies presence + a stable substring rather than exact versions for the
apt-managed tools.

## pip-installed (in dedicated venvs)

| Tool | Path | Pin | requirements file |
|---|---|---|---|
| MHDDoS deps | `/opt/MHDDoS/.venv` | from submodule pin | `tests/integration/vendor/MHDDoS/requirements.txt` |
| scapy | `/opt/scapy-venv` | `scapy==2.7.0` | inline |
| mitmproxy | `/opt/mitmproxy-venv` | `mitmproxy==12.2.3` | inline |

`pip install --require-hashes` is not used because upstream
`requirements.txt` (MHDDoS) does not ship hashes. We pin minor versions
and trust the submodule pin for transitives.

## Release tarballs (sha256-verified)

All sha256 values below were captured from the upstream-published
checksum files (or `assets[].digest` on GitHub's release API) on
2026-05-20. Bumping a pin requires refreshing the hash from the same
authoritative source — never compute it locally on an arbitrary download.

| Tool | Version | sha256 | URL |
|---|---|---|---|
| vegeta | 12.13.0 | `e8759ce45c14e18374bdccd3ba6068197bc3a9f9b7e484db3837f701b9d12e61` | `github.com/tsenart/vegeta/releases/download/v12.13.0/vegeta_12.13.0_linux_amd64.tar.gz` |
| k6 | 2.0.0 | `2ae87d976f6cdba17185bdd980d8819a3a98e9092c6f0638cd58272ecefc8b90` | `github.com/grafana/k6/releases/download/v2.0.0/k6-v2.0.0-linux-amd64.tar.gz` |
| nuclei | 3.8.0 | `cd4ea43c88b50af8ab96eb6ad3fb4debd8e9d51efaff4d4c2d99106041578943` | `github.com/projectdiscovery/nuclei/releases/download/v3.8.0/nuclei_3.8.0_linux_amd64.zip` |
| dnscrypt-proxy | 2.1.15 | `bc43b8fe41a5962e5fc39e3887c1d881d51f1ad87221fef85b48fc0b35f19244` | `github.com/DNSCrypt/dnscrypt-proxy/releases/download/2.1.15/dnscrypt-proxy-linux_x86_64-2.1.15.tar.gz` |
| cloudflared | 2026.5.0 | `0095e46fdc88855d801c4d304cb1f5dd4bd656116c47ab94c2ad0ae7cda1c7ec` | `github.com/cloudflare/cloudflared/releases/download/2026.5.0/cloudflared-linux-amd64` |

Mismatch behaviour: `setup-attacker.sh::install_release` aborts with a
non-zero exit when the computed sha256 disagrees with the pin above.
There is no "soft fallthrough" mode — a drift here is a release-asset
republish or a tampered mirror, both of which warrant a manual review.

## source builds

| Tool | Upstream | Pinned tag | Build command |
|---|---|---|---|
| hyenae-ng | https://github.com/r-richter/hyenae-ng | `v0.10` | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build && sudo cmake --install build --prefix /usr/local` |

## kernel modules

| Module | Source | Notes |
|---|---|---|
| pktgen | upstream kernel | Enabled via `/etc/modules-load.d/pktgen.conf`; udev rule sets default queue depth |

## Submodules

| Path | Upstream | Pin (date captured) |
|---|---|---|
| `tests/integration/vendor/MHDDoS` | `https://github.com/MatrixTM/MHDDoS` | `804f989712d9bbaa14d329436724aecb71b0d0e7` (2026-05-01 HEAD of `main`) |

## Bump policy

- Patch / minor releases: bumped opportunistically; pin update + matrix
  rerun is sufficient.
- Major releases: require a follow-up review pass on the consuming
  suites' assertion ranges (rate floors / latency ceilings).
- Pin commit for a submodule: bump via the procedure in
  `tests/integration/vendor/README.md`.

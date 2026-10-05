# eBPFsentinel demo lab

Two labs you start alone on one Linux host, with nothing to sign up for. The
tutorials in the documentation run every command against them, and the videos
were recorded from them.

| Lab | Start | What it shows |
|---|---|---|
| Compose | `sudo ./demo.sh up` | A SYN flood stopped and its source blocked, a card number caught inside TLS, a workload cut off for calling an AI provider |
| GitOps | `./gitops/gitops.sh up` | The same rule arriving on a fleet through a commit, and leaving it through a revert |

## What the host needs

- Linux 6.9 or later with BTF (`/sys/kernel/btf/vmlinux`). Ubuntu 24.04 with
  its HWE kernel, Debian 13 and Fedora 41 all qualify.
- Docker with the compose plugin.
- On Ubuntu 24.04 and later, user namespaces allowed for the session:
  `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`. The
  script checks and says so rather than changing it.
- For the GitOps lab, `git` and `curl`. kind, kubectl, helm and the Argo CD
  manifest are fetched into `gitops/.run/` at pinned versions and checked
  against their SHA-256; `down` deletes them.

## Compose lab

```bash
sudo ./demo.sh up
sudo ./demo.sh agent status
sudo ./demo.sh down
```

It creates a bridge named `esdemo0` on `172.30.66.0/24` and attaches the
agent to it alone, so nothing the lab does touches the host's own uplink.

| Container | Address | Role |
|---|---|---|
| `warden`, `agent` | host network | the published images, rootless agent and its broker |
| `target` | `172.30.66.1` | the protected service, HTTP on 80 and HTTPS on 443 |
| `attacker` | `172.30.66.66` | sends the flood |
| `app` | `172.30.66.20` | a workload speaking TLS through OpenSSL |

The agent's configuration is `agent.yaml`, read as it stands by every
scenario.

## GitOps lab

```bash
./gitops/gitops.sh up
eval "$(./gitops/gitops.sh env)"
git clone git://localhost:9418/estate.git
./gitops/gitops.sh down
```

A one-node kind cluster running Argo CD (core install) and a git server. The
repository it serves holds the agent's Helm chart, vendored under `chart/`,
and its values in `agent.yaml`, seeded from `gitops/estate/`. Argo CD keeps
the `ebpfsentinel` namespace equal to the repository, polling it every
fifteen seconds with no jitter, and reads chart and values from one source so
both always come from the same commit; `gitops/changes/` holds the change the
tutorial commits.

`EBPFSENTINEL_TAG` picks the image tag in both labs, `latest` by default.
`AGENT_CHART`, an absolute path to a checkout's `charts/ebpfsentinel`, points
the GitOps lab at it instead of the published chart.

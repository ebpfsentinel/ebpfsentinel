# eBPFsentinel demo lab

Two labs you start alone on one Linux host, with nothing to sign up for. The
tutorials in the documentation run every command against them, and the videos
were recorded from them.

It is retrieved from the release and from nowhere else, like every other
artifact:

```bash
curl -fsSLO https://github.com/ebpfsentinel/ebpfsentinel-release/releases/latest/download/ebpfsentinel-demo.tar.gz
tar xzf ebpfsentinel-demo.tar.gz && cd ebpfsentinel-demo
```

That tarball is this directory, with two differences: an `.env` pinning
`EBPFSENTINEL_TAG` to the release it came from, so the lab keeps running that
release rather than following `latest`, and no `compose.local.yaml`, since
`--local` builds from a checkout and a tarball is not one. Its checksum and
signature are in the release's `SHA256SUMS`, verifiable with `policy/verify.sh`
from the same release.

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

`up` pulls the published agent and warden images. From a checkout of the
repository, `up --local` builds both from it instead, through
`compose.local.yaml`, which changes nothing else
about the lab: same bridge, same addresses, same `agent.yaml`. Use it on a host
with no access to the published images, and when testing a patch, since the lab
then runs that patch rather than the last published build. The agent image
copies `../ebpf-out/`, which the pinned nightly fills through
`cargo xtask ebpf-build` from the repository root, and `--local` checks that
directory before building rather than failing inside Docker. The mode is
remembered in `.run/`, so `down` and `agent` act on the lab that `up` created.

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

`EBPFSENTINEL_TAG` picks the image tag in both labs, `latest` by default, and
the `.env` of a downloaded lab sets it to that release: compose reads that file
on its own, and `gitops.sh` reads the one key out of it so both labs run the
same release.
`AGENT_CHART`, an absolute path to a checkout's `charts/ebpfsentinel`, points
the GitOps lab at it instead of the published chart.

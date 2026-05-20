# tests/integration/vendor — Third-Party Attack Tools

Submodules vendored here are runtime-invoked attack/load tools used by
the BATS integration suites. They are **not** linked into any
ebpfsentinel binary; they execute as separate processes against the
agent's data plane to generate adversarial traffic.

| Path | Upstream | License | Pinned commit | Used by |
|---|---|---|---|---|
| `MHDDoS/` | https://github.com/MatrixTM/MHDDoS | GPL-3.0 | `804f989712d9bbaa14d329436724aecb71b0d0e7` | Suites 41 (L7 attacks), 63 (DLP MITM stress) |

## MHDDoS — Notice

- **License**: GPL-3.0 (preserved at `MHDDoS/LICENSE`)
- **Usage**: runtime fork only — invoked from L7-attack BATS suites to
  generate traffic against the ebpfsentinel agent. No ebpfsentinel
  source file imports, includes, or transcribes MHDDoS code.
- **AGPL boundary**: ebpfsentinel is AGPL-3.0; MHDDoS is GPL-3.0. Both
  copyleft licenses are compatible *for runtime invocation as separate
  processes*, which is the only mode of use here.
- **Distribution obligation**: redistribute MHDDoS's `LICENSE` file
  (present via submodule) and disclose upstream URL + pinned commit.

## Updating a pin

```bash
cd tests/integration/vendor/<name>
git fetch --depth 1 origin <new-commit>
git checkout <new-commit>
cd -
git add tests/integration/vendor/<name>
# Update the pin recorded in vagrant/provision/TOOL_VERSIONS.md to match.
```

Pin bumps must be reviewed for new transitive dependencies and any
upstream advisories before merging.

## Bootstrapping in CI / Vagrant

The attacker VM provisioner (`vagrant/provision/setup-attacker.sh`)
runs `git submodule update --init --depth 1 --recursive` against the
mounted project tree, then sets up a Python venv at `/opt/MHDDoS/.venv`
from `MHDDoS/requirements.txt`. No outbound clones happen at test
runtime; everything is staged at provision time.

# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| x.x.x   | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in eBPFsentinel, please report it responsibly via one of these channels:

**GitHub Security Advisories** (preferred): [Report a vulnerability](https://github.com/ebpfsentinel/ebpfsentinel/security/advisories/new)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Impact assessment (if possible)
- Suggested fix (if any)

### Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | 48 hours |
| Initial assessment | 5 business days |
| Fix development | 14 days (critical), 30 days (high), 90 days (medium/low) |
| Public disclosure | After fix is released |

We will coordinate disclosure with the reporter. Credit is given to reporters unless they request anonymity.

## Security Measures

### Code Safety

- `#![forbid(unsafe_code)]` on domain, ports, application, and infrastructure crates
- `#![deny(unsafe_code)]` on adapters with one targeted `#[allow]` for eBPF ring buffer parsing
- Zero `.unwrap()` policy in production code

### Input Validation

- Regex patterns: 10 MiB size limit, 200 nesting depth (DoS prevention)
- Config rule count limits: 4096 rules max per domain (OOM prevention)
- DNS label length and query depth limits
- All user input sanitized before logging (injection prevention)

### Dependency Management

- `cargo deny check` enforces license compliance and blocks known advisories
- `cargo audit` runs daily in CI (`security.yml`)
- SBOM generated in CycloneDX format on every release
- Yanked crates and unknown registries are denied

### Authentication & Transport

- TLS 1.3 via rustls (aws-lc backend) for REST and gRPC
- JWT (RS256) and OIDC (JWKS) authentication
- API keys with constant-time comparison
- RBAC with admin, operator, and viewer roles

### eBPF Safety

- All eBPF programs pass the kernel verifier (memory safety, bounded execution)
- No arbitrary kernel memory access
- `CAP_BPF` + `CAP_NET_ADMIN` required (principle of least privilege)
- Ring buffer backpressure prevents kernel-side resource exhaustion

### CI/CD Security

| Workflow | Schedule | Checks |
|----------|----------|--------|
| `security.yml` | Daily + push to main | `cargo audit`, `cargo deny`, unsafe code audit, SBOM |
| `ci.yml` | Every PR | Format, clippy (`-D warnings`), full test suite |

## File Permissions

The agent warns at startup if config or key files are world-readable. Recommended permissions:

```bash
chmod 640 /etc/ebpfsentinel/config.yaml
chmod 600 /etc/ebpfsentinel/server.key
chmod 600 /etc/ebpfsentinel/jwt.pub
```

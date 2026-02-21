# Contributing to eBPFsentinel

## Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Linux kernel | 5.17+ with BTF | eBPF program loading |
| Rust stable | 1.93+ | Userspace crates |
| Rust nightly | latest | eBPF kernel programs (`bpfel-unknown-none`) |
| `bpftool` | any | eBPF program inspection |
| `iproute2` | any | Network interface management |
| `protoc` | 3.x+ | gRPC proto compilation |
| `jq` | any | Integration tests |
| [BATS](https://github.com/bats-core/bats-core) | 1.10+ | Integration tests |
| [grpcurl](https://github.com/fullstorydev/grpcurl) | any | gRPC integration tests |

### Install Rust Toolchains

```bash
# Stable (userspace)
rustup toolchain install stable
rustup component add rustfmt clippy rust-src

# Nightly (eBPF programs)
rustup toolchain install nightly --component rust-src
```

## Building

### Userspace Agent

```bash
cargo build                         # Debug build
cargo build --release               # Release build
```

### eBPF Kernel Programs

```bash
cargo xtask ebpf-build              # Builds all 5 eBPF programs with nightly
```

The eBPF programs are built for `bpfel-unknown-none` (little-endian BPF) and output to each program's `target/` directory. The `xtask` crate orchestrates this.

### Full Build

```bash
cargo xtask ebpf-build && cargo build --release
```

## Testing

### Unit Tests

```bash
cargo test                          # All crates (requires protoc)
cargo test -p domain                # Domain crate only (930+ tests, no protoc needed)
cargo test -p infrastructure        # Config + infra tests
cargo test -p adapters              # Adapter tests (requires protoc)
```

The domain crate has zero external dependencies and contains the bulk of the tests. This is the fastest feedback loop during development.

### Integration Tests

67 tests across 10 BATS suites that test the agent as a running binary:

| Suite | Tests | Description |
|-------|-------|-------------|
| 01 | Agent lifecycle | Start, stop, SIGHUP reload, invalid config |
| 02 | REST API health | healthz, readyz, status, metrics, OpenAPI |
| 03 | Firewall CRUD | Create, list, delete rules via REST |
| 04 | Domain APIs | IPS, L7, rate limit, threat intel, alerts, audit |
| 05 | gRPC streaming | Health, reflection, alert subscriptions |
| 06 | eBPF programs | veth pair setup, program attachment (needs root) |
| 07 | Authentication | JWT, OIDC, RBAC roles, token expiry |
| 08 | TLS | HTTPS, gRPC-TLS, certificate validation |
| 09 | Docker | Image build, compose up/down, healthcheck |
| 10 | Kubernetes | Minikube DaemonSet, liveness probes |

```bash
cd tests/integration

# Run all suites
make test

# Run a single suite
make test-suite SUITE=01-agent-lifecycle

# Run in a Vagrant VM (full isolation)
make vagrant-up && make test-vm

# K8s tests (requires minikube)
make test-k8s
```

### Benchmarks

10 criterion benchmark suites covering all domain engines:

```bash
cargo bench -p domain               # Run all benchmarks
cargo bench -p domain -- firewall   # Filter by name
```

Benchmark results generate HTML reports in `target/criterion/`. The CI workflow detects regressions on PRs.

## Code Style

### Formatting

```bash
cargo fmt --check                   # Verify
cargo fmt                           # Fix
```

Standard Rust formatting (no custom `rustfmt.toml` overrides).

### Linting

Zero-warning policy with pedantic clippy:

```bash
cargo clippy -- -D warnings         # Must pass with zero warnings
```

Lint configuration is in `Cargo.toml` under `[workspace.lints.clippy]`:
- `all = deny` (baseline)
- `pedantic = warn` (stricter checks)
- A few targeted allows (`module_name_repetitions`, `must_use_candidate`, etc.)

### Dependency Audit

```bash
cargo deny check                    # License, advisory, ban, source checks
```

The `deny.toml` policy:
- 8 approved licenses (MIT, Apache-2.0, BSD-2/3-Clause, ISC, Unicode-3.0, Unicode-DFS-2016, OpenSSL)
- Yanked crates denied
- Unknown registries and git sources denied
- Vulnerability advisories denied

## Architecture

### Hexagonal / DDD

```
domain ← ports ← application
                ← infrastructure
                ← adapters ← agent (binary)
```

**Rules:**
- `domain` depends on **nothing** — pure business logic, `#![forbid(unsafe_code)]`
- `ports` defines traits consumed by adapters (primary) and implemented by adapters (secondary)
- `application` orchestrates domain engines via port traits
- `adapters` implements port traits (HTTP, gRPC, eBPF, redb storage)
- `agent` wires everything together at startup

### Domain Engines

Each security domain follows the same structure:

```
crates/domain/src/<domain>/
├── entity.rs     # Types, enums, constants
├── engine.rs     # Core logic (stateless evaluation)
├── error.rs      # Domain-specific errors (thiserror)
└── mod.rs        # Re-exports
```

Engines are pure functions that take input + rules and return decisions. No I/O, no async, no side effects.

### eBPF Programs

Each eBPF program is a separate crate under `crates/ebpf-programs/`:

```
crates/ebpf-programs/<program>/
├── Cargo.toml    # Dependencies: aya-ebpf, ebpf-common, network-types
└── src/
    └── main.rs   # #![no_std] #![no_main] entry point
```

Programs share types via `ebpf-common` (`#[repr(C)]` structs).

### Adding a New Security Domain

1. Create engine in `crates/domain/src/<name>/` (entity, engine, error, mod)
2. Add port traits in `crates/ports/src/primary/<name>.rs` and `secondary/` if needed
3. Create app service in `crates/application/src/<name>_service_impl.rs`
4. Add HTTP handlers in `crates/adapters/src/http/<name>_handler.rs`
5. Wire routes in `crates/adapters/src/http/router.rs`
6. Add config section in `crates/infrastructure/src/config.rs`
7. Initialize in `crates/agent/src/startup.rs`
8. Add tests at each layer

## CI Pipeline

| Workflow | Trigger | Jobs |
|----------|---------|------|
| `ci.yml` | Push/PR to main/develop | Format, clippy, tests, cargo-deny, cargo-audit, release build |
| `integration.yml` | Push/PR to main, nightly | BATS suites 01-05, 07-08 (API, auth, TLS) |
| `benchmarks.yml` | Push/PR to main | Compile check + full run, regression detection |
| `security.yml` | Push to main, daily | Audit, deny, unsafe code audit, SBOM generation |

All CI jobs must pass before merging.

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes following the patterns above
3. Ensure all checks pass locally:
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo test
   cargo deny check
   ```
4. Write or update tests for your changes
5. Open a PR targeting `main`
6. CI must pass (format, lint, test, audit)

## Error Handling

- `thiserror` for library/domain errors (typed, matchable)
- `anyhow` for application-level errors (agent binary)
- Zero `.unwrap()` in production code
- `Result<T, DomainError>` for all domain engine methods

## Security

- Never commit credentials, keys, or secrets
- Config files containing secrets should be `chmod 640` or stricter
- All regex patterns are compiled with size and nesting limits (DoS prevention)
- Rule count limits are enforced at config load time
- See the [Security section in README.md](README.md#security) for the full security posture

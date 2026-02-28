# eBPFsentinel — Multi-stage Docker build
#
# Build:  docker build -t ebpfsentinel .
# Run:    docker run --privileged --network host -v ./config:/etc/ebpfsentinel ebpfsentinel
#
# Multi-arch:
#   docker buildx build --platform linux/amd64,linux/arm64 -t ebpfsentinel .

# ── Stage 1: Build eBPF programs + userspace agent ──────────────────

FROM rust:bookworm AS builder

# Install build dependencies: protoc (gRPC codegen) + nightly toolchain + BPF linker
RUN apt-get update && \
    apt-get install -y --no-install-recommends protobuf-compiler && \
    rm -rf /var/lib/apt/lists/* && \
    rustup toolchain install nightly --no-self-update --component rust-src && \
    cargo +nightly install bpf-linker

WORKDIR /build

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock rust-toolchain.toml deny.toml ./
COPY .cargo/ .cargo/
COPY crates/ crates/
COPY proto/ proto/

# Build eBPF programs (nightly, bpfel-unknown-none target)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo xtask ebpf-build

# Build userspace agent (stable, release mode — strip+LTO via profile.release)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release --bin ebpfsentinel-agent

# ── Stage 2: Minimal runtime image ──────────────────────────────────
#
# distroless/cc: glibc + libgcc + ca-certificates
# No shell, no package manager, no SUID binaries → minimal attack surface.

FROM gcr.io/distroless/cc-debian12

LABEL org.opencontainers.image.title="eBPFsentinel" \
    org.opencontainers.image.description="eBPF network security agent" \
    org.opencontainers.image.source="https://github.com/ebpfsentinel/ebpfsentinel" \
    org.opencontainers.image.licenses="AGPL-3.0-only"

# Copy agent binary (stripped + LTO by cargo profile.release)
COPY --from=builder /build/target/release/ebpfsentinel-agent \
    /usr/local/bin/ebpfsentinel-agent

# Copy ALL eBPF programs (auto-discovered — xtask copies them all here)
COPY --from=builder /build/target/bpfel-unknown-none/release/ \
    /usr/local/lib/ebpfsentinel/

# Copy default configuration
COPY config/ebpfsentinel.yaml /etc/ebpfsentinel/config.yaml

# Directory containing all eBPF program binaries
ENV EBPF_PROGRAM_DIR=/usr/local/lib/ebpfsentinel

# HTTP API, gRPC, Prometheus metrics
EXPOSE 8080 50051 9090

# Healthcheck uses the agent's built-in CLI (no curl needed)
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD ["ebpfsentinel-agent", "health"]

ENTRYPOINT ["ebpfsentinel-agent"]
CMD ["--config", "/etc/ebpfsentinel/config.yaml"]

# eBPFsentinel — Multi-stage Docker build
#
# Build:  docker build -t ebpfsentinel .
# Run:    docker run --privileged --network host -v ./config:/etc/ebpfsentinel ebpfsentinel
#
# Multi-arch:
#   docker buildx build --platform linux/amd64,linux/arm64 -t ebpfsentinel .

# ── Stage 1: Build eBPF programs + userspace agent ──────────────────

FROM rust:bookworm AS builder

ARG TARGETARCH

# Install build dependencies: protoc (gRPC codegen) + musl toolchain (static linking)
# + nightly toolchain + BPF linker
RUN apt-get update && \
    apt-get install -y --no-install-recommends protobuf-compiler musl-tools cmake && \
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

# Install musl target for the toolchain resolved by rust-toolchain.toml, then build
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    case "${TARGETARCH}" in \
        arm64) MUSL_TARGET="aarch64-unknown-linux-musl" ;; \
        *)     MUSL_TARGET="x86_64-unknown-linux-musl" ;; \
    esac && \
    rustup target add "${MUSL_TARGET}" && \
    cargo build --release --target "${MUSL_TARGET}" --bin ebpfsentinel-agent && \
    cp "/build/target/${MUSL_TARGET}/release/ebpfsentinel-agent" /build/ebpfsentinel-agent

# ── Stage 2: Minimal runtime image ──────────────────────────────────
#
# distroless/static: ca-certificates only — no libc, no shell, no package manager.
# Requires a fully statically-linked binary (musl).

FROM gcr.io/distroless/static-debian13

LABEL org.opencontainers.image.title="eBPFsentinel" \
    org.opencontainers.image.description="eBPF network security agent" \
    org.opencontainers.image.source="https://github.com/ebpfsentinel/ebpfsentinel" \
    org.opencontainers.image.licenses="AGPL-3.0-only"

# Copy agent binary (statically linked, stripped + LTO by cargo profile.release)
COPY --from=builder /build/ebpfsentinel-agent /usr/local/bin/ebpfsentinel-agent

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

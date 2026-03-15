# eBPFsentinel — Multi-stage Docker build
#
# Build:  docker build -t ebpfsentinel .
# Run:    docker run --privileged --network host -v ./config:/etc/ebpfsentinel ebpfsentinel
#
# Multi-arch:
#   docker buildx build --platform linux/amd64,linux/arm64 -t ebpfsentinel .

# ── Stage 1: Build eBPF programs (always on amd64 — output is arch-independent) ──

FROM --platform=linux/amd64 rust:bookworm AS ebpf-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends llvm-dev && \
    rm -rf /var/lib/apt/lists/* && \
    rustup toolchain install nightly --no-self-update --component rust-src && \
    if ! command -v llvm-config >/dev/null 2>&1; then \
        LLC=$(ls /usr/bin/llvm-config-* 2>/dev/null | sort -V | tail -1); \
        [ -n "$LLC" ] && ln -sf "$LLC" /usr/bin/llvm-config; \
    fi && \
    cargo +nightly install bpf-linker

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .cargo/ .cargo/
COPY crates/ crates/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo xtask ebpf-build && \
    mkdir -p /build/ebpf-out && \
    find crates/ebpf-programs/*/target/bpfel-unknown-none/release \
      -maxdepth 1 -type f ! -name '*.d' ! -name '*.fingerprint' \
      -exec cp {} /build/ebpf-out/ \;

# ── Stage 2: Build userspace agent (native arch) ─────────────────────

FROM rust:bookworm AS agent-builder

ARG TARGETARCH

RUN apt-get update && \
    apt-get install -y --no-install-recommends protobuf-compiler musl-tools cmake && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml deny.toml ./
COPY .cargo/ .cargo/
COPY crates/ crates/
COPY proto/ proto/

# Copy pre-built eBPF programs so include_bytes!() macros resolve
COPY --from=ebpf-builder /build/ebpf-out/ /build/ebpf-out/
COPY --from=ebpf-builder /build/crates/ebpf-programs/ /build/crates/ebpf-programs/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    case "${TARGETARCH}" in \
        arm64) MUSL_TARGET="aarch64-unknown-linux-musl" ;; \
        *)     MUSL_TARGET="x86_64-unknown-linux-musl" ;; \
    esac && \
    rustup target add "${MUSL_TARGET}" && \
    cargo build --release --target "${MUSL_TARGET}" --bin ebpfsentinel-agent && \
    cp "/build/target/${MUSL_TARGET}/release/ebpfsentinel-agent" /build/ebpfsentinel-agent

# ── Stage 3: Minimal runtime image ──────────────────────────────────
#
# distroless/static: ca-certificates only — no libc, no shell, no package manager.
# Requires a fully statically-linked binary (musl).

FROM gcr.io/distroless/static-debian13

LABEL org.opencontainers.image.title="eBPFsentinel" \
    org.opencontainers.image.description="eBPF network security agent" \
    org.opencontainers.image.source="https://github.com/ebpfsentinel/ebpfsentinel" \
    org.opencontainers.image.licenses="AGPL-3.0-only"

COPY --from=agent-builder /build/ebpfsentinel-agent /usr/local/bin/ebpfsentinel-agent
COPY --from=ebpf-builder /build/ebpf-out/ /usr/local/lib/ebpfsentinel/
COPY config/ebpfsentinel.yaml /etc/ebpfsentinel/config.yaml

ENV EBPF_PROGRAM_DIR=/usr/local/lib/ebpfsentinel

EXPOSE 8080 50051 9090

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD ["ebpfsentinel-agent", "health"]

ENTRYPOINT ["ebpfsentinel-agent"]
CMD ["--config", "/etc/ebpfsentinel/config.yaml"]

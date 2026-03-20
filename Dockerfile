# eBPFsentinel — Multi-stage Docker build
#
# Build:  docker build -t ebpfsentinel .
# Run:    docker run --privileged --network host -v ./config:/etc/ebpfsentinel ebpfsentinel
#
# eBPF programs must be pre-built before docker build:
#   cargo xtask ebpf-build
#
# The CI workflow handles this automatically (build-ebpf job → build-images job).

# ── Stage 1: Build userspace agent ───────────────────────────────────

FROM rust:bookworm AS agent-builder

ARG TARGETARCH

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        protobuf-compiler musl-tools cmake flex bison wget && \
    rm -rf /var/lib/apt/lists/*

# Build static libpcap against musl for fully static linking
RUN PCAP_VERSION=1.10.6 && \
    wget -qO- "https://www.tcpdump.org/release/libpcap-${PCAP_VERSION}.tar.xz" | tar xJ && \
    cd "libpcap-${PCAP_VERSION}" && \
    CC=musl-gcc ./configure --disable-shared --prefix=/usr/local/musl && \
    make -j"$(nproc)" && \
    make install && \
    cd .. && rm -rf "libpcap-${PCAP_VERSION}"

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml deny.toml ./
COPY .cargo/ .cargo/
COPY crates/ crates/
COPY proto/ proto/

ENV LIBPCAP_LIBDIR=/usr/local/musl/lib

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    case "${TARGETARCH}" in \
        arm64) MUSL_TARGET="aarch64-unknown-linux-musl" ;; \
        *)     MUSL_TARGET="x86_64-unknown-linux-musl" ;; \
    esac && \
    rustup target add "${MUSL_TARGET}" && \
    RUSTFLAGS="-L native=/usr/local/musl/lib" \
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

COPY --from=agent-builder /build/ebpfsentinel-agent /usr/local/bin/ebpfsentinel-agent

# Copy pre-built eBPF programs (built by CI or `cargo xtask ebpf-build`)
COPY ebpf-out/ /usr/local/lib/ebpfsentinel/

COPY config/ebpfsentinel.yaml /etc/ebpfsentinel/config.yaml

ENV EBPF_PROGRAM_DIR=/usr/local/lib/ebpfsentinel

EXPOSE 8080 50051 9090

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD ["ebpfsentinel-agent", "health"]

ENTRYPOINT ["ebpfsentinel-agent"]
CMD ["--config", "/etc/ebpfsentinel/config.yaml"]

# eBPFsentinel — Multi-stage Docker build
#
# Build:  docker build -t ebpfsentinel .
# Run:    docker run --cap-add SYS_ADMIN --cap-add NET_RAW --network host \
#           --security-opt apparmor=unconfined \
#           -v ./config:/etc/ebpfsentinel \
#           -v /sys/fs/bpf:/sys/fs/bpf ebpfsentinel
#
# The /sys/fs/bpf bind-mount is required: a container's /sys is read-only, so
# the launcher cannot create the bpffs mountpoint there without a writable
# /sys/fs/bpf. The host bpffs is writable; bind it in. (On a host without a
# bpffs mounted, `--tmpfs /sys/fs/bpf` works too.) CAP_NET_RAW lets the launcher
# pre-open the AF_PACKET pcap pool — drop it if you never capture.
#
# eBPF loads only through a BPF token (user-namespace feature): the entrypoint
# launcher needs CAP_SYS_ADMIN + the ability to create a user namespace, then
# execs the agent unprivileged inside it. The long-running agent holds no host
# capabilities.
#
# Packet capture works rootless: the launcher pre-opens the AF_PACKET sockets
# (CAP_NET_RAW, in Docker's default capability set) and passes the fds to the
# agent. libpcap is statically linked (musl) below, so the runtime image needs
# no extra package. If you run with `--cap-drop ALL`, re-add `--cap-add NET_RAW`.
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
        protobuf-compiler musl-tools cmake flex bison wget linux-libc-dev && \
    rm -rf /var/lib/apt/lists/*

# Symlink Linux kernel headers into musl's include path so libpcap finds them
RUN MUSL_INC="$(find /usr/include -maxdepth 1 -name '*-linux-musl*' -type d | head -1)" && \
    ln -s /usr/include/linux "$MUSL_INC/linux" && \
    ln -s /usr/include/asm-generic "$MUSL_INC/asm-generic" && \
    ln -s /usr/include/$(uname -m)-linux-gnu/asm "$MUSL_INC/asm" && \
    ln -s /usr/include/mtd "$MUSL_INC/mtd"

# Build static libpcap against musl for fully static linking
RUN PCAP_VERSION=1.10.6 && \
    PCAP_SHA256="ec97d1206bdd19cb6bdd043eaa9f0037aa732262ec68e070fd7c7b5f834d5dfc" && \
    wget -qO /tmp/libpcap.tar.xz "https://www.tcpdump.org/release/libpcap-${PCAP_VERSION}.tar.xz" && \
    echo "${PCAP_SHA256}  /tmp/libpcap.tar.xz" | sha256sum -c - && \
    tar xJf /tmp/libpcap.tar.xz && rm -f /tmp/libpcap.tar.xz && \
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

# Build the agent and the BPF token launcher (both static, musl). eBPF loads
# only through a token, a user-namespace feature: the launcher sets up the
# delegated bpffs in a child userns and execs the agent there (rootless).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    case "${TARGETARCH}" in \
        arm64) MUSL_TARGET="aarch64-unknown-linux-musl" ;; \
        *)     MUSL_TARGET="x86_64-unknown-linux-musl" ;; \
    esac && \
    rustup target add "${MUSL_TARGET}" && \
    RUSTFLAGS="-L native=/usr/local/musl/lib" \
    cargo build --release --target "${MUSL_TARGET}" \
        --bin ebpfsentinel-agent --bin warden-token && \
    cp "/build/target/${MUSL_TARGET}/release/ebpfsentinel-agent" /build/ebpfsentinel-agent && \
    cp "/build/target/${MUSL_TARGET}/release/warden-token" /build/warden-token && \
    mkdir -p /build/captures-dir

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
COPY --from=agent-builder /build/warden-token /usr/local/bin/warden-token

# Copy pre-built eBPF programs (built by CI or `cargo xtask ebpf-build`)
COPY ebpf-out/ /usr/local/lib/ebpfsentinel/

# 0640: the agent rejects a world-readable config (it may hold secrets). The
# source file is 0644 in git, so tighten it as it lands in the image. Left
# root-owned: under Docker the launcher keeps the agent as root (Docker permits
# the root userns self-map), so root reads it directly. (Under a containerd-based
# Kubernetes the config comes from a ConfigMap, not this baked copy.)
COPY --chmod=0640 config/ebpfsentinel.yaml /etc/ebpfsentinel/config.yaml

# distroless has no shell — create the directory in the builder stage and COPY it.
COPY --from=agent-builder /build/captures-dir /var/lib/ebpfsentinel/captures

ENV EBPF_PROGRAM_DIR=/usr/local/lib/ebpfsentinel

EXPOSE 8080 50051 9090

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD ["ebpfsentinel-agent", "health"]

# The launcher bootstraps the BPF token in a child user namespace, then execs
# the agent (appending CMD) inside it. CMD carries the agent's own arguments.
ENTRYPOINT ["/usr/local/bin/warden-token", "--bpffs", "/sys/fs/bpf/ebpfsentinel", "/usr/local/bin/ebpfsentinel-agent"]
CMD ["--config", "/etc/ebpfsentinel/config.yaml"]

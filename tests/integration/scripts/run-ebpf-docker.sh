#!/usr/bin/env bash
# run-ebpf-docker.sh — Run eBPF integration tests inside a privileged Docker container
#
# The container runs as root so it can create network namespaces, attach
# eBPF programs, and use bpftool.  The host binary + eBPF programs are
# bind-mounted (read-only) into the container.
#
# Usage:
#   bash scripts/run-ebpf-docker.sh                  # all eBPF suites
#   bash scripts/run-ebpf-docker.sh --suite 11       # single suite
#   bash scripts/run-ebpf-docker.sh --api             # non-eBPF API suites only
#   bash scripts/run-ebpf-docker.sh --all             # every suite (API + eBPF)
#   bash scripts/run-ebpf-docker.sh --skip-build       # skip cargo build
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_ROOT="$(cd "$INTEGRATION_DIR/../.." && pwd)"
SUITE_DIR="${INTEGRATION_DIR}/suites"

DOCKER_IMAGE="${DOCKER_IMAGE:-ubuntu:rolling}"
CONTAINER_NAME="ebpfsentinel-testrunner-$$"

# ── Options ───────────────────────────────────────────────────────
SUITE_FILTER=""
RUN_API=false
RUN_EBPF=true
RUN_ALL=false
SKIP_BUILD=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --suite)       SUITE_FILTER="$2"; shift 2 ;;
        --api)         RUN_API=true; RUN_EBPF=false; shift ;;
        --all)         RUN_ALL=true; shift ;;
        --skip-build)  SKIP_BUILD=true; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Pre-flight ────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo "ERROR: docker not found" >&2
    exit 1
fi

if ! docker info &>/dev/null 2>&1; then
    echo "ERROR: Docker daemon not running" >&2
    exit 1
fi

# ── Build if needed ───────────────────────────────────────────────
if [ "$SKIP_BUILD" = "false" ]; then
    echo "Building agent (release)..."
    (cd "$PROJECT_ROOT" && cargo build --release --bin ebpfsentinel-agent)
    echo ""
fi

if [ ! -x "${PROJECT_ROOT}/target/release/ebpfsentinel-agent" ]; then
    echo "ERROR: agent binary not found at target/release/ebpfsentinel-agent" >&2
    echo "Run: cargo build --release --bin ebpfsentinel-agent" >&2
    exit 1
fi

if [ ! -f "${PROJECT_ROOT}/target/bpfel-unknown-none/release/xdp-firewall" ]; then
    echo "ERROR: eBPF programs not found at target/bpfel-unknown-none/release/" >&2
    echo "Run: cargo xtask ebpf-build" >&2
    exit 1
fi

# ── Build suite list ──────────────────────────────────────────────

API_SUITES=(
    01-agent-lifecycle
    02-rest-api-health
    03-rest-api-firewall
    04-rest-api-domains
    05-grpc-streaming
    07-authentication
    08-tls
    16-rest-api-ddos
    17-rest-api-extended
)

EBPF_SUITES=(
    11-ebpf-firewall-scenarios
    12-ebpf-ids-scenarios
    13-ebpf-ips-scenarios
    14-ebpf-ratelimit-scenarios
    18-ebpf-threatintel-scenarios
    19-ebpf-conntrack-scenarios
    20-ebpf-dns-scenarios
    21-ebpf-loadbalancer-scenarios
    22-ebpf-nat-scenarios
    23-ebpf-ddos-scenarios
)

SUITES=()

if [ -n "$SUITE_FILTER" ]; then
    # Single suite by number or name
    for f in "${SUITE_DIR}"/*"${SUITE_FILTER}"*.bats; do
        [ -f "$f" ] && SUITES+=("$(basename "$f")")
    done
    if [ ${#SUITES[@]} -eq 0 ]; then
        echo "ERROR: no suite matching '${SUITE_FILTER}'" >&2
        exit 1
    fi
elif [ "$RUN_ALL" = "true" ]; then
    for s in "${API_SUITES[@]}"; do SUITES+=("${s}.bats"); done
    for s in "${EBPF_SUITES[@]}"; do SUITES+=("${s}.bats"); done
elif [ "$RUN_API" = "true" ]; then
    for s in "${API_SUITES[@]}"; do SUITES+=("${s}.bats"); done
else
    for s in "${EBPF_SUITES[@]}"; do SUITES+=("${s}.bats"); done
fi

# Build bats args
BATS_ARGS=()
for s in "${SUITES[@]}"; do
    BATS_ARGS+=("tests/integration/suites/${s}")
done

echo "=== eBPFsentinel Docker Test Runner ==="
echo "Suites:  ${SUITES[*]}"
echo "Image:   ${DOCKER_IMAGE}"
echo ""

# ── Detect host bpftool ───────────────────────────────────────────
BPFTOOL_MOUNT=""
HOST_BPFTOOL="$(command -v bpftool 2>/dev/null || true)"
if [ -n "$HOST_BPFTOOL" ] && [ -x "$HOST_BPFTOOL" ]; then
    BPFTOOL_MOUNT="-v ${HOST_BPFTOOL}:/usr/sbin/bpftool:ro"
fi

# ── Run in Docker ─────────────────────────────────────────────────
# shellcheck disable=SC2086
docker run --rm \
    --name "$CONTAINER_NAME" \
    --privileged \
    --network host \
    --pid host \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /sys/kernel/btf:/sys/kernel/btf:ro \
    -v /sys/kernel/debug:/sys/kernel/debug:ro \
    -v "${PROJECT_ROOT}:/workspace:ro" \
    $BPFTOOL_MOUNT \
    -w /workspace \
    -e AGENT_BIN=/workspace/target/release/ebpfsentinel-agent \
    -e EBPF_PROGRAM_DIR=/workspace/target/bpfel-unknown-none/release \
    "$DOCKER_IMAGE" \
    bash -c "
        # Install test dependencies
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null 2>&1
        # Enable universe repo for bats on Ubuntu
        apt-get install -y -qq software-properties-common >/dev/null 2>&1 || true
        add-apt-repository -y universe >/dev/null 2>&1 || true
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y -qq \
            curl jq iproute2 iputils-ping ncat nmap procps bc openssl \
            >/dev/null 2>&1 || true

        # Install bats (not in default Ubuntu repos)
        if ! command -v bats &>/dev/null; then
            apt-get install -y -qq git >/dev/null 2>&1
            git clone --depth 1 https://github.com/bats-core/bats-core.git /tmp/bats-core >/dev/null 2>&1
            /tmp/bats-core/install.sh /usr/local >/dev/null 2>&1
        fi

        # Install grpcurl
        if ! command -v grpcurl &>/dev/null; then
            curl -fsSL -o /tmp/grpcurl.deb 'https://github.com/fullstorydev/grpcurl/releases/download/v1.9.3/grpcurl_1.9.3_linux_amd64.deb' \
                && dpkg -i /tmp/grpcurl.deb >/dev/null 2>&1 \
                && rm -f /tmp/grpcurl.deb \
                || echo 'WARN: grpcurl install failed'
        fi

        # Generate TLS certs and JWT tokens
        bash tests/integration/scripts/generate-certs.sh >/dev/null 2>&1
        bash tests/integration/scripts/generate-jwt-keys.sh >/dev/null 2>&1

        echo '--- Test environment ready ---'
        echo \"Kernel:  \$(uname -r)\"
        echo \"Bats:    \$(bats --version)\"
        echo \"grpcurl: \$(grpcurl --version 2>&1 || echo 'not available')\"
        echo \"Root:    \$(id -u)\"
        bpftool version 2>/dev/null || echo 'bpftool: not available'
        echo ''

        # Run suites
        bats --timing ${BATS_ARGS[*]}
    "

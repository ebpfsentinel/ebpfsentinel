#!/usr/bin/env bats
# 09-docker.bats — Docker build and deployment tests
#
# Requires: Docker Engine on native Linux with kernel 5.17+ and BTF.

load '../lib/helpers'

DOCKER_IMAGE="ebpfsentinel:integration-test"
CONTAINER_NAME="ebpfsentinel-test"

setup_file() {
    if ! command -v docker &>/dev/null; then
        skip "Docker not installed"
    fi

    if ! docker info &>/dev/null 2>&1; then
        skip "Docker daemon not running"
    fi

    # Check kernel BTF support (required for CO-RE eBPF programs)
    if [ ! -f /sys/kernel/btf/vmlinux ]; then
        skip "Kernel BTF not available (/sys/kernel/btf/vmlinux missing)"
    fi

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    export TEST_COMPOSE="${PROJECT_ROOT}/tests/integration/fixtures/docker-compose-test.yml"
}

teardown_file() {
    if [ -n "$TEST_COMPOSE" ] && [ -f "$TEST_COMPOSE" ]; then
        docker compose -f "$TEST_COMPOSE" down -v 2>/dev/null || true
    fi
}

# ── Tests ──────────────────────────────────────────────────────────

@test "docker build succeeds" {
    command -v docker &>/dev/null || skip "Docker not installed"
    docker info &>/dev/null 2>&1 || skip "Docker daemon not running"

    run docker build --network=host -t "$DOCKER_IMAGE" "$PROJECT_ROOT"
    [ "$status" -eq 0 ]
}

@test "docker compose up results in healthy container" {
    command -v docker &>/dev/null || skip "Docker not installed"
    docker info &>/dev/null 2>&1 || skip "Docker daemon not running"
    [ -f /sys/kernel/btf/vmlinux ] || skip "Kernel BTF not available"

    docker compose -f "$TEST_COMPOSE" up -d

    # Wait for Docker healthcheck to pass
    local attempts=0
    local max_attempts=30
    local health="starting"

    while [ "$attempts" -lt "$max_attempts" ] && [ "$health" != "healthy" ]; do
        health="$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null)" || health="starting"
        sleep 2
        attempts=$((attempts + 1))
    done

    [ "$health" = "healthy" ]
}

@test "healthz accessible via agent CLI inside container" {
    command -v docker &>/dev/null || skip "Docker not installed"
    docker info &>/dev/null 2>&1 || skip "Docker daemon not running"
    [ -f /sys/kernel/btf/vmlinux ] || skip "Kernel BTF not available"

    run docker exec "$CONTAINER_NAME" /usr/local/bin/ebpfsentinel-agent health
    [ "$status" -eq 0 ]
    assert_contains "$output" "ok"
}

@test "docker compose down cleans up" {
    command -v docker &>/dev/null || skip "Docker not installed"
    docker info &>/dev/null 2>&1 || skip "Docker daemon not running"

    docker compose -f "$TEST_COMPOSE" down -v

    local running
    running="$(docker ps -q --filter "name=$CONTAINER_NAME" 2>/dev/null)" || true
    [ -z "$running" ]
}

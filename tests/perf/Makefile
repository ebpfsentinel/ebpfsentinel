# eBPFsentinel — performance test runner (run on the agent VM, as root).
#
# These suites reuse the integration harness (../integration/lib + the agent VM).
# From the host, prefer `make -C ../integration test-perf`; this Makefile is the
# convenience entry when already on the agent VM.

PERF_DIR := $(shell pwd)
BATS ?= bats

.PHONY: help
help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

.PHONY: all
all: ## Run every perf suite (requires root)
	sudo $(BATS) --timing $(PERF_DIR)/*.bats

.PHONY: throughput
throughput: ## Throughput overhead benchmark (perf/01)
	sudo $(BATS) --timing $(PERF_DIR)/01-performance-benchmark.bats

.PHONY: feature-overhead
feature-overhead: ## Per-feature CPU overhead (perf/02)
	sudo $(BATS) --timing $(PERF_DIR)/02-ebpf-feature-overhead.bats

.PHONY: map-ops
map-ops: ## Control-plane map-op latency (perf/03)
	sudo $(BATS) --timing $(PERF_DIR)/03-ebpf-map-operation-bench.bats

.PHONY: high-pps
high-pps: ## High-pps / XDP-drop savings (perf/04)
	sudo $(BATS) --timing $(PERF_DIR)/04-pktgen-high-pps.bats

.PHONY: feature-overhead-extended
feature-overhead-extended: ## Isolated scrub/DNS/QoS/conntrack overhead (perf/05)
	sudo $(BATS) --timing $(PERF_DIR)/05-ebpf-feature-overhead-extended.bats

.PHONY: nat-dlp
nat-dlp: ## NAT translation + DLP uprobe overhead (perf/06)
	sudo $(BATS) --timing $(PERF_DIR)/06-ebpf-feature-overhead-nat-dlp.bats

.PHONY: suite
suite: ## Run a single suite: make suite SUITE=02-ebpf-feature-overhead
	sudo $(BATS) --timing $(PERF_DIR)/$(SUITE).bats

# tests/integration/Makefile — Integration test orchestration
#
# Usage:
#   make test            Run all suites locally or in VM
#   make test-suite SUITE=01-agent-lifecycle
#   make test-k8s        K8s suite only
#   make vagrant-up      Start VM
#   make vagrant-ssh     SSH into VM
#   make clean           Remove temp files
#   make nuke            Destroy VM and all artifacts

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

# ── Directories ────────────────────────────────────────────────────
INTEGRATION_DIR := $(shell pwd)
PROJECT_ROOT := $(INTEGRATION_DIR)/../..
VAGRANT_DIR := $(INTEGRATION_DIR)/vagrant
SUITE_DIR := $(INTEGRATION_DIR)/suites
SCRIPT_DIR := $(INTEGRATION_DIR)/scripts

# ── Vagrant ────────────────────────────────────────────────────────

.PHONY: vagrant-up
vagrant-up: ## Start the test VM
	cd $(VAGRANT_DIR) && vagrant up

.PHONY: vagrant-ssh
vagrant-ssh: ## SSH into the test VM
	cd $(VAGRANT_DIR) && vagrant ssh

.PHONY: vagrant-halt
vagrant-halt: ## Stop the test VM
	cd $(VAGRANT_DIR) && vagrant halt

.PHONY: vagrant-destroy
vagrant-destroy: ## Destroy the test VM
	cd $(VAGRANT_DIR) && vagrant destroy -f

.PHONY: vagrant-provision
vagrant-provision: ## Re-provision the test VM
	cd $(VAGRANT_DIR) && vagrant provision

# ── Tests ──────────────────────────────────────────────────────────

.PHONY: test
test: test-local ## Run all integration test suites (alias for test-local)

.PHONY: test-local
test-local: ## Run all suites locally (requires agent binary built)
	$(SCRIPT_DIR)/run-in-vm.sh --skip-build

.PHONY: test-build-and-run
test-build-and-run: ## Build agent, then run all suites locally
	$(SCRIPT_DIR)/run-in-vm.sh

.PHONY: test-vm
test-vm: vagrant-up ## Run all suites inside the VM
	cd $(VAGRANT_DIR) && vagrant ssh -c \
		'cd /home/vagrant/ebpfsentinel/tests/integration && bash scripts/run-in-vm.sh --skip-build'

.PHONY: test-k8s
test-k8s: ## Run K8s suite only (locally or in VM)
	$(SCRIPT_DIR)/run-in-vm.sh --suite 10-kubernetes --skip-build

.PHONY: test-suite
test-suite: ## Run a single suite: make test-suite SUITE=01-agent-lifecycle
ifndef SUITE
	$(error SUITE is required, e.g. make test-suite SUITE=01-agent-lifecycle)
endif
	bats --timing $(SUITE_DIR)/$(SUITE).bats

# ── eBPF scenario & performance tests ────────────────────────────

.PHONY: test-ebpf-scenarios
test-ebpf-scenarios: ## Run eBPF suites 11-14, 18-23 via sudo (binary mode)
	sudo bats --timing \
		$(SUITE_DIR)/11-ebpf-firewall-scenarios.bats \
		$(SUITE_DIR)/12-ebpf-ids-scenarios.bats \
		$(SUITE_DIR)/13-ebpf-ips-scenarios.bats \
		$(SUITE_DIR)/14-ebpf-ratelimit-scenarios.bats \
		$(SUITE_DIR)/18-ebpf-threatintel-scenarios.bats \
		$(SUITE_DIR)/19-ebpf-conntrack-scenarios.bats \
		$(SUITE_DIR)/20-ebpf-dns-scenarios.bats \
		$(SUITE_DIR)/21-ebpf-loadbalancer-scenarios.bats \
		$(SUITE_DIR)/22-ebpf-nat-scenarios.bats \
		$(SUITE_DIR)/23-ebpf-ddos-scenarios.bats

.PHONY: test-ebpf-docker-runner
test-ebpf-docker-runner: ## Run eBPF suites in privileged Docker (no sudo needed)
	bash $(SCRIPT_DIR)/run-ebpf-docker.sh --skip-build

.PHONY: test-ebpf-docker-all
test-ebpf-docker-all: ## Run ALL suites (API + eBPF) in privileged Docker
	bash $(SCRIPT_DIR)/run-ebpf-docker.sh --all --skip-build

.PHONY: test-ebpf-docker-suite
test-ebpf-docker-suite: ## Run single suite in Docker: make test-ebpf-docker-suite SUITE=11
ifndef SUITE
	$(error SUITE is required, e.g. make test-ebpf-docker-suite SUITE=11)
endif
	bash $(SCRIPT_DIR)/run-ebpf-docker.sh --suite $(SUITE) --skip-build

.PHONY: test-performance
test-performance: ## Run performance benchmark suite 15 (requires root)
	sudo bats --timing $(SUITE_DIR)/15-performance-benchmark.bats

.PHONY: test-ebpf-all
test-ebpf-all: test-ebpf-scenarios test-performance ## Run all eBPF + performance suites

.PHONY: test-perf-docker
test-perf-docker: ## Comprehensive Docker performance tests (requires root + Docker)
	sudo bash $(SCRIPT_DIR)/perf-test-docker.sh --skip-build

.PHONY: test-perf-docker-quick
test-perf-docker-quick: ## Quick Docker performance test (~2-3 min)
	sudo bash $(SCRIPT_DIR)/perf-test-docker.sh --skip-build --quick

.PHONY: test-perf-docker-soak
test-perf-docker-soak: ## Docker soak test with leak detection (~20 min)
	sudo bash $(SCRIPT_DIR)/perf-test-docker.sh --skip-build --soak

.PHONY: test-ebpf-vm
test-ebpf-vm: vagrant-up ## Run eBPF + performance suites inside the VM
	cd $(VAGRANT_DIR) && vagrant ssh -c \
		'cd /home/vagrant/ebpfsentinel/tests/integration && sudo bats --timing \
			suites/11-ebpf-firewall-scenarios.bats \
			suites/12-ebpf-ids-scenarios.bats \
			suites/13-ebpf-ips-scenarios.bats \
			suites/14-ebpf-ratelimit-scenarios.bats \
			suites/15-performance-benchmark.bats \
			suites/18-ebpf-threatintel-scenarios.bats \
			suites/19-ebpf-conntrack-scenarios.bats \
			suites/20-ebpf-dns-scenarios.bats \
			suites/21-ebpf-loadbalancer-scenarios.bats \
			suites/22-ebpf-nat-scenarios.bats \
			suites/23-ebpf-ddos-scenarios.bats'

.PHONY: test-perf-vagrant
test-perf-vagrant: ## Binary vs Docker perf comparison in Vagrant VM
	bash $(SCRIPT_DIR)/perf-test-vagrant.sh

.PHONY: test-perf-vagrant-quick
test-perf-vagrant-quick: ## Quick binary vs Docker perf comparison in VM (~10 min)
	bash $(SCRIPT_DIR)/perf-test-vagrant.sh --quick

.PHONY: test-perf-host-to-vm
test-perf-host-to-vm: ## Host-to-VM perf test over VirtualBox private network
	bash $(SCRIPT_DIR)/perf-test-host-to-vm.sh

.PHONY: test-perf-host-to-vm-quick
test-perf-host-to-vm-quick: ## Quick host-to-VM perf test
	bash $(SCRIPT_DIR)/perf-test-host-to-vm.sh --quick

# ── 2-VM topology (agent + attacker VMs) ─────────────────────────

.PHONY: vagrant-2vm-up
vagrant-2vm-up: ## Start both agent and attacker VMs
	cd $(VAGRANT_DIR) && vagrant up agent attacker

.PHONY: vagrant-2vm-halt
vagrant-2vm-halt: ## Stop both VMs
	cd $(VAGRANT_DIR) && vagrant halt agent attacker

.PHONY: vagrant-2vm-destroy
vagrant-2vm-destroy: ## Destroy both VMs
	cd $(VAGRANT_DIR) && vagrant destroy -f agent attacker

.PHONY: vagrant-ssh-agent
vagrant-ssh-agent: ## SSH into the agent VM
	cd $(VAGRANT_DIR) && vagrant ssh agent

.PHONY: vagrant-ssh-attacker
vagrant-ssh-attacker: ## SSH into the attacker VM
	cd $(VAGRANT_DIR) && vagrant ssh attacker

.PHONY: test-2vm
test-2vm: vagrant-2vm-up ## Run all suites via 2-VM topology
	$(SCRIPT_DIR)/run-in-2vm.sh --skip-provision

.PHONY: test-2vm-suite
test-2vm-suite: ## Run single suite in 2-VM mode: make test-2vm-suite SUITE=11
ifndef SUITE
	$(error SUITE is required, e.g. make test-2vm-suite SUITE=11)
endif
	$(SCRIPT_DIR)/run-in-2vm.sh --skip-provision --suite $(SUITE)

.PHONY: test-2vm-ebpf
test-2vm-ebpf: vagrant-2vm-up ## Run eBPF scenario suites via 2-VM topology
	$(SCRIPT_DIR)/run-in-2vm.sh --skip-provision --ebpf

.PHONY: test-2vm-perf
test-2vm-perf: vagrant-2vm-up ## Run performance suites via 2-VM topology
	$(SCRIPT_DIR)/run-in-2vm.sh --skip-provision --performance

.PHONY: test-2vm-perf-comparison
test-2vm-perf-comparison: vagrant-2vm-up ## Binary vs Docker perf comparison in 2-VM
	$(SCRIPT_DIR)/run-in-2vm.sh --skip-provision --perf-comparison

.PHONY: test-2vm-perf-comparison-quick
test-2vm-perf-comparison-quick: vagrant-2vm-up ## Quick binary vs Docker comparison
	$(SCRIPT_DIR)/run-in-2vm.sh --skip-provision --perf-comparison --quick

# ── Utilities ────────────────────────────────────────────────────

.PHONY: sync-agent
sync-agent: ## Sync local binary + Docker image to agent VM (no build)
	bash $(SCRIPT_DIR)/sync-to-agent-vm.sh

.PHONY: sync-agent-binary
sync-agent-binary: ## Sync local binary only to agent VM
	bash $(SCRIPT_DIR)/sync-to-agent-vm.sh --binary

.PHONY: sync-agent-docker
sync-agent-docker: ## Sync local Docker image only to agent VM
	bash $(SCRIPT_DIR)/sync-to-agent-vm.sh --docker

.PHONY: docker-push-agent
docker-push-agent: ## Build Docker image on host and push to agent VM
	bash $(SCRIPT_DIR)/push-docker-image.sh

.PHONY: docker-push-agent-nocache
docker-push-agent-nocache: ## Build (no cache) and push Docker image to agent VM
	bash $(SCRIPT_DIR)/push-docker-image.sh --no-cache

.PHONY: docker-push-agent-only
docker-push-agent-only: ## Push existing Docker image to agent VM (skip build)
	bash $(SCRIPT_DIR)/push-docker-image.sh --skip-build

# ── Resource Matrix Benchmark ──────────────────────────────────────

.PHONY: bench-resource-matrix
bench-resource-matrix: ## Run resource matrix benchmark (CPU/RSS per feature × volume)
	bash $(SCRIPT_DIR)/benchmark-resource-matrix.sh

.PHONY: bench-resource-matrix-2vm
bench-resource-matrix-2vm: ## Run resource matrix benchmark in 2VM mode
	bash $(SCRIPT_DIR)/benchmark-resource-matrix.sh --2vm

.PHONY: bench-resource-merge
bench-resource-merge: ## Merge two resource matrix reports: make bench-resource-merge F1=report1.json F2=report2.json
	bash $(SCRIPT_DIR)/benchmark-resource-matrix.sh --merge $(F1) $(F2)

# ── Cleanup ────────────────────────────────────────────────────────

.PHONY: clean
clean: ## Remove temp files, stop any running agents
	rm -rf /tmp/ebpfsentinel-test-data*
	rm -rf /tmp/ebpfsentinel-test-certs
	rm -rf /tmp/ebpfsentinel-test-jwt
	rm -f /tmp/ebpfsentinel-test.pid
	rm -f /tmp/ebpfsentinel-test.log
	rm -f /tmp/ebpfsentinel-prepared-*.yaml
	rm -f /tmp/ebpfsentinel-test-config-*.yaml
	rm -f /tmp/ebpfsentinel-test-invalid-*.yaml
	rm -f /tmp/ebpfsentinel-test-auth-*.yaml
	rm -f /tmp/ebpfsentinel-test-tls-*.yaml
	rm -f /tmp/ebpfsentinel-test-ebpf-*.yaml
	rm -f /tmp/ebpfsentinel-benchmark-latest.json
	rm -f /tmp/ebpfsentinel-perf-report-*.json
	rm -f /tmp/ebpfsentinel-host-perf-*.json
	rm -f /tmp/ebpfsentinel-perf-compose-*.yml
	rm -rf /tmp/ebpfsentinel-perf-data-*

.PHONY: nuke
nuke: clean vagrant-destroy ## Destroy everything: VMs, temp files

# ── Help ───────────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-26s\033[0m %s\n", $$1, $$2}'

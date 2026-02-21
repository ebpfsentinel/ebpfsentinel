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
test-ebpf-scenarios: ## Run eBPF scenario suites 11-14 (requires root)
	sudo bats --timing \
		$(SUITE_DIR)/11-ebpf-firewall-scenarios.bats \
		$(SUITE_DIR)/12-ebpf-ids-scenarios.bats \
		$(SUITE_DIR)/13-ebpf-ips-scenarios.bats \
		$(SUITE_DIR)/14-ebpf-ratelimit-scenarios.bats

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
			suites/15-performance-benchmark.bats'

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

.PHONY: prepare-docker-image
prepare-docker-image: ## Save Docker image tar for VM injection
	docker save -o $(PROJECT_ROOT)/ebpfsentinel-image.tar ebpfsentinel-agent:latest
	@echo "Image saved to $(PROJECT_ROOT)/ebpfsentinel-image.tar"

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
nuke: clean vagrant-destroy ## Destroy everything: VM, temp files

# ── Help ───────────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-26s\033[0m %s\n", $$1, $$2}'

SHELL := /usr/bin/env bash

DOCKER_COMPOSE ?= docker compose
SERVICE ?= jinnguard-sandbox
JINN_GUARD_SECRET ?= dev-secret-not-for-production
JINN_GUARD_SOCKET ?= /tmp/jinnguard.sock
JINN_GUARD_AUDIT ?= /tmp/jinnguard-audit.log
JINN_GUARD_LINEAGE ?= /tmp/jinnguard-lineage.json
JINN_GUARD_MCP_PORT ?= 4850

.PHONY: help docker-build dev-shell build fmt clippy test check daemon demo smoke clean docker-check docker-smoke docker-down runtime-build runtime-smoke runtime-agent-probe runtime-agent-shell runtime-logs runtime-down

help:
	@printf '%s\n' \
	  'Jinn Guard Rust sandbox targets:' \
	  '  make docker-build   Build the Docker sandbox image' \
	  '  make dev-shell      Open a shell inside the sandbox' \
	  '  make build          cargo build --workspace --locked' \
	  '  make check          fmt + clippy + tests on the current machine' \
	  '  make docker-check   fmt + clippy + tests inside Docker' \
	  '  make daemon         Run the daemon with local dev paths' \
	  '  make demo           Run the Step 1 Python broker demo' \
	  '  make smoke          Build, start daemon, and run Step 1 demo' \
	  '  make docker-smoke   Run the smoke test inside Docker' \
	  '  make runtime-smoke  Run Step 2 mandatory mediation runtime smoke'

docker-build:
	$(DOCKER_COMPOSE) build $(SERVICE)

dev-shell:
	$(DOCKER_COMPOSE) run --rm $(SERVICE) bash

build:
	cargo build --workspace --locked

fmt:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets

test:
	cargo test --workspace --locked

check: fmt clippy test

daemon:
	JINN_GUARD_SECRET="$(JINN_GUARD_SECRET)" \
	JINN_GUARD_SOCKET="$(JINN_GUARD_SOCKET)" \
	JINNGUARD_SOCKET="$(JINN_GUARD_SOCKET)" \
	JINN_GUARD_AUDIT="$(JINN_GUARD_AUDIT)" \
	JINN_GUARD_LINEAGE="$(JINN_GUARD_LINEAGE)" \
	JINN_GUARD_MCP_PORT="$(JINN_GUARD_MCP_PORT)" \
	./scripts/sandbox_run_daemon.sh

demo:
	JINN_GUARD_SECRET="$(JINN_GUARD_SECRET)" \
	JINN_GUARD_SOCKET="$(JINN_GUARD_SOCKET)" \
	JINNGUARD_SOCKET="$(JINN_GUARD_SOCKET)" \
	python3 examples/step1_capability_broker_demo.py

smoke:
	JINN_GUARD_SECRET="$(JINN_GUARD_SECRET)" \
	JINN_GUARD_SOCKET="$(JINN_GUARD_SOCKET)" \
	JINNGUARD_SOCKET="$(JINN_GUARD_SOCKET)" \
	JINN_GUARD_MCP_PORT="$(JINN_GUARD_MCP_PORT)" \
	./scripts/sandbox_smoke.sh

docker-check:
	$(DOCKER_COMPOSE) run --rm $(SERVICE) make check

docker-smoke:
	$(DOCKER_COMPOSE) run --rm $(SERVICE) make smoke

docker-down:
	$(DOCKER_COMPOSE) down

runtime-build:
	$(DOCKER_COMPOSE) -f docker-compose.runtime.yml build jinnguard-broker locked-agent

runtime-smoke:
	./scripts/runtime_smoke.sh

runtime-agent-probe:
	./scripts/runtime_agent_probe.sh

runtime-agent-shell:
	./scripts/runtime_agent_shell.sh

runtime-logs:
	./scripts/runtime_logs.sh

runtime-down:
	./scripts/runtime_down.sh

clean:
	cargo clean
	rm -f "$(JINN_GUARD_SOCKET)" "$(JINN_GUARD_AUDIT)" "$(JINN_GUARD_AUDIT).db" "$(JINN_GUARD_LINEAGE)"

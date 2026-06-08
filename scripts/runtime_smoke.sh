#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.runtime.yml}"
DOCKER_COMPOSE="${DOCKER_COMPOSE:-docker compose}"

cleanup() {
  $DOCKER_COMPOSE -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

$DOCKER_COMPOSE -f "$COMPOSE_FILE" build jinnguard-broker locked-agent
$DOCKER_COMPOSE -f "$COMPOSE_FILE" up --abort-on-container-exit --exit-code-from locked-agent locked-agent

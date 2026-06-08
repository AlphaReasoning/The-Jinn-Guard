#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.runtime.yml}"
DOCKER_COMPOSE="${DOCKER_COMPOSE:-docker compose}"

$DOCKER_COMPOSE -f "$COMPOSE_FILE" up -d jinnguard-broker
$DOCKER_COMPOSE -f "$COMPOSE_FILE" run --rm --no-deps locked-agent python3 -i

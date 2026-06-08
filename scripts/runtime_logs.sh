#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.runtime.yml}"
DOCKER_COMPOSE="${DOCKER_COMPOSE:-docker compose}"

$DOCKER_COMPOSE -f "$COMPOSE_FILE" logs --tail=200 "$@"

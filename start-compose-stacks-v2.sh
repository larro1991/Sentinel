#!/bin/bash
# start-compose-stacks.sh v4 — fire-and-forget, --no-recreate
# Docker restart:unless-stopped handles boot recovery. This script starts
# any stacks not yet running. --no-recreate avoids orphan containers when
# Docker already restored a container before this script runs.

log() { echo "[$(date +%H:%M:%S)] $*"; }

log "Ensuring services-network exists"
docker network create services-network 2>/dev/null || true

# Infra stacks first (db/redis must be up before dependents)
for dir in /opt/docker/paperless-pg /opt/docker/paperless-redis /opt/docker/postgres; do
    [ -f "$dir/docker-compose.yml" ] && (cd "$dir" && docker compose up -d --no-recreate 2>/dev/null) &
done

INFRA_NAMES="paperless-pg paperless-redis postgres"

for dir in /opt/docker/*/; do
    name=$(basename "$dir")
    echo "$INFRA_NAMES" | grep -qw "$name" && continue
    [ -f "$dir/docker-compose.yml" ] || continue
    (cd "$dir" && docker compose up -d --no-recreate 2>/dev/null) &
done

for dir in /Main/services/*/; do
    name=$(basename "$dir")
    [ -f "$dir/docker-compose.yml" ] || continue
    (cd "$dir" && docker compose up -d --no-recreate 2>/dev/null) &
done

for dir in /Main/appdata/pm-agent /Main/appdata/Crucible; do
    [ -f "$dir/docker-compose.yml" ] && (cd "$dir" && docker compose up -d --no-recreate 2>/dev/null) &
done

log "All compose stacks launched (background) — exiting"

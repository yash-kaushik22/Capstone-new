#!/usr/bin/env bash
# Runs on the production host (called by .github/workflows/deploy.yml).
#   IMAGE_PREFIX=ghcr.io/org/secureshare bash remote-deploy.sh <tag>
# Pulls the tagged images, restarts the stack and rolls back to the previous
# tag if the services do not become healthy.
set -euo pipefail

TAG="${1:?usage: remote-deploy.sh <tag>}"
ENV_FILE=deploy/.env
STATE=.deployed-tag
[ -f "$ENV_FILE" ] || { echo "missing $ENV_FILE"; exit 1; }
[ -d secrets ] || { echo "missing ./secrets (run scripts/gen-secrets.mjs once)"; exit 1; }

PREVIOUS="$(cat "$STATE" 2>/dev/null || true)"
compose() { TAG="$1" IMAGE_PREFIX="$IMAGE_PREFIX" docker compose --env-file "$ENV_FILE" "${@:2}"; }

healthy() {
  for _ in $(seq 1 40); do
    local bad=0
    for svc in api authority; do
      status="$(docker inspect -f '{{.State.Health.Status}}' "$(compose "$TAG" ps -q "$svc")" 2>/dev/null || echo missing)"
      [ "$status" = healthy ] || bad=1
    done
    [ "$bad" = 0 ] && return 0
    sleep 3
  done
  return 1
}

echo "Deploying $TAG (previous: ${PREVIOUS:-none})"
compose "$TAG" pull --quiet
compose "$TAG" up -d --remove-orphans

if healthy; then
  echo "$TAG" > "$STATE"
  docker image prune -f > /dev/null
  echo "Deployed $TAG"
else
  echo "Services unhealthy after deploying $TAG" >&2
  compose "$TAG" logs --tail 80 api authority >&2 || true
  if [ -n "$PREVIOUS" ]; then
    echo "Rolling back to $PREVIOUS" >&2
    compose "$PREVIOUS" up -d --remove-orphans
  fi
  exit 1
fi

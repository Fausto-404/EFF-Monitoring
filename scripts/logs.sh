#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

if docker compose version >/dev/null 2>&1; then
  docker compose logs --tail=200 "$@"
elif command -v docker-compose >/dev/null 2>&1; then
  docker-compose logs --tail=200 "$@"
else
  echo "未找到 Docker Compose。" >&2
  exit 1
fi

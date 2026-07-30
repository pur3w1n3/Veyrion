#!/usr/bin/env bash
set -euo pipefail

PACK_ROOT="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$PACK_ROOT/compose.dev.yml"
REMOVE_VOLUMES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --volumes) REMOVE_VOLUMES=1; shift ;;
    -h|--help)
      echo "Usage: Stop-SandboxPack.sh [--volumes]"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

ARGS=(compose -f "$COMPOSE_FILE" down --remove-orphans)
if [[ "$REMOVE_VOLUMES" -eq 1 ]]; then
  ARGS+=(--volumes)
fi
docker "${ARGS[@]}"
echo "Veyrion development Sandbox Pack stopped."

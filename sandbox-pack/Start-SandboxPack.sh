#!/usr/bin/env bash
# Linux/macOS counterpart to Start-SandboxPack.ps1
set -euo pipefail

PACK_ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$PACK_ROOT/.." && pwd)"
RUNTIME_ROOT="$PACK_ROOT/.runtime"
COMPOSE_FILE="$PACK_ROOT/compose.dev.yml"
STATE_FILE="$RUNTIME_ROOT/state.json"
RUNTIME_TAG="127.0.0.1:5000/veyrion/artifact-runtime:dev"
SKIP_RUNTIME_BUILD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-runtime-build) SKIP_RUNTIME_BUILD=1; shift ;;
    -h|--help)
      echo "Usage: Start-SandboxPack.sh [--skip-runtime-build]"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

docker info --format '{{.ServerVersion}}' >/dev/null

mkdir -p "$RUNTIME_ROOT"
docker compose -f "$COMPOSE_FILE" up -d --remove-orphans registry

if [[ "$SKIP_RUNTIME_BUILD" -eq 0 ]]; then
  docker build \
    --file "$PACK_ROOT/artifact-runtime.Dockerfile" \
    --tag "$RUNTIME_TAG" \
    "$REPO_ROOT"
  docker push "$RUNTIME_TAG"
fi

RUNTIME_URI="$(docker image inspect --format '{{index .RepoDigests 0}}' "$RUNTIME_TAG")"
if [[ ! "$RUNTIME_URI" =~ ^127\.0\.0\.1:5000/veyrion/artifact-runtime@sha256:[0-9a-f]{64}$ ]]; then
  echo "The local registry did not return a digest-pinned artifact runtime reference." >&2
  echo "Run without --skip-runtime-build first." >&2
  exit 1
fi

cat > "$STATE_FILE" <<EOF
{
  "schemaVersion": 2,
  "runtime": "docker-desktop-runc",
  "capability": "TRUSTED_DOCKER",
  "networkMode": "none",
  "features": [
    "artifact-readonly-mount-v1",
    "network-deny-v1",
    "non-root-v1",
    "read-only-rootfs-v1",
    "resource-budget-v1",
    "trace-tmpfs-v1"
  ],
  "artifactRuntimeImageUri": "${RUNTIME_URI}"
}
EOF

echo "Trusted internal JAR runtime: ${RUNTIME_URI}"
echo "State file: ${STATE_FILE}"
echo "WARNING: TRUSTED_DOCKER uses --network none: external network and external DNS are unavailable; the target probe uses container-internal loopback. Docker runc is not a hardened hostile-code boundary." >&2

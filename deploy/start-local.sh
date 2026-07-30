#!/usr/bin/env bash
# Linux/macOS counterpart to Start-Veyrion.ps1 for local (non-Compose) development.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ARTIFACTS="${ARTIFACTS:-$ROOT/samples}"
BACKEND_PORT="${BACKEND_PORT:-18080}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"
WITH_DOCKER_RUNTIME=0
REBUILD_RUNTIME_IMAGE=0

usage() {
  cat <<'EOF'
Usage: deploy/start-local.sh [options]

Options:
  --artifacts DIR          Authorized artifact root (must stay inside workspace)
  --backend-port N         Control Plane port (default 18080)
  --frontend-port N        Vite GUI port (default 5173)
  --java-home DIR          JDK 17+ home (sets JAVA_HOME)
  --with-docker-runtime    Enable host TRUSTED_DOCKER worker via sandbox-pack
  --rebuild-runtime-image  Rebuild/push artifact-runtime before start
  -h, --help               Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts) ARTIFACTS="$2"; shift 2 ;;
    --backend-port) BACKEND_PORT="$2"; shift 2 ;;
    --frontend-port) FRONTEND_PORT="$2"; shift 2 ;;
    --java-home) export JAVA_HOME="$2"; export PATH="$JAVA_HOME/bin:$PATH"; shift 2 ;;
    --with-docker-runtime) WITH_DOCKER_RUNTIME=1; shift ;;
    --rebuild-runtime-image) REBUILD_RUNTIME_IMAGE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -n "${JAVA_HOME:-}" ]]; then
  JAVA_BIN="$JAVA_HOME/bin/java"
else
  JAVA_BIN="$(command -v java)"
fi
[[ -x "$JAVA_BIN" ]] || { echo "Java 17+ is required." >&2; exit 1; }

JAVA_MAJOR="$("$JAVA_BIN" -XshowSettings:properties -version 2>&1 \
  | sed -n 's/.*java\.specification\.version = //p' | head -n1 | sed 's/^1\.//')"
if [[ -z "$JAVA_MAJOR" || "$JAVA_MAJOR" -lt 17 ]]; then
  echo "Veyrion requires Java 17 or newer (active: ${JAVA_MAJOR:-unknown})." >&2
  echo "Example: deploy/start-local.sh --java-home /usr/lib/jvm/temurin-17" >&2
  exit 1
fi

if [[ "$BACKEND_PORT" -eq "$FRONTEND_PORT" ]]; then
  echo "Backend and frontend ports must differ." >&2
  exit 1
fi

mkdir -p "$ARTIFACTS"
ARTIFACTS="$(cd "$ARTIFACTS" && pwd)"
case "$ARTIFACTS" in
  "$ROOT"|"$ROOT"/*) ;;
  *) echo "Artifacts must stay inside the Veyrion workspace: $ROOT" >&2; exit 1 ;;
esac

if [[ "$WITH_DOCKER_RUNTIME" -eq 1 ]]; then
  STATE_FILE="$ROOT/sandbox-pack/.runtime/state.json"
  if [[ -f "$STATE_FILE" && "$REBUILD_RUNTIME_IMAGE" -eq 0 ]]; then
    "$ROOT/sandbox-pack/Start-SandboxPack.sh" --skip-runtime-build
  else
    "$ROOT/sandbox-pack/Start-SandboxPack.sh"
  fi
  [[ -f "$STATE_FILE" ]] || { echo "Sandbox Pack startup failed." >&2; exit 1; }
  VEYRION_ARTIFACT_RUNTIME_IMAGE_URI="$(sed -n 's/.*"artifactRuntimeImageUri"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$STATE_FILE" | head -n1)"
  export VEYRION_ARTIFACT_RUNTIME_IMAGE_URI
  if [[ ! "$VEYRION_ARTIFACT_RUNTIME_IMAGE_URI" =~ ^[a-z0-9.-]+(:[0-9]{1,5})?/([A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$ ]]; then
    echo "Sandbox Pack returned an invalid trusted artifact runtime image." >&2
    exit 1
  fi
fi

if [[ ! -f frontend/node_modules/vite/bin/vite.js ]]; then
  npm ci --prefix frontend
fi
NODE_BIN="$(command -v node)"

mvn -q -Dmaven.repo.local=.m2 -DskipTests package
mvn -q -Dmaven.repo.local=.m2 dependency:build-classpath -Dmdep.outputFile=target/runtime-classpath.txt
CP="target/classes:$(tr -d '\r\n' < target/runtime-classpath.txt)"

WORKER_FLAG=false
[[ "$WITH_DOCKER_RUNTIME" -eq 1 ]] && WORKER_FLAG=true

exec "$JAVA_BIN" -cp "$CP" com.aq.jvmsentinel.dev.DevLauncherMain \
  --workspace "$ROOT" \
  --artifacts "$ARTIFACTS" \
  --backend-port "$BACKEND_PORT" \
  --frontend-port "$FRONTEND_PORT" \
  --node "$NODE_BIN" \
  --docker-artifact-worker "$WORKER_FLAG"

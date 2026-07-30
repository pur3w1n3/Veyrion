#!/bin/sh
set -eu

ROOT="${VEYRION_ARTIFACT_ROOT:-/data/artifacts}"
DB="${VEYRION_DATABASE:-${ROOT}/.veyrion/control-plane.db}"
BIND="${VEYRION_BIND:-0.0.0.0}"
PORT="${VEYRION_PORT:-18080}"
TOKEN_FILE="${ROOT}/.veyrion/mutation.token"

mkdir -p "${ROOT}/.veyrion"

if [ -n "${VEYRION_TOKEN:-}" ]; then
  TOKEN="${VEYRION_TOKEN}"
elif [ -f "${TOKEN_FILE}" ]; then
  TOKEN="$(tr -d '\r\n' < "${TOKEN_FILE}")"
else
  TOKEN="local-demo"
fi

# Persist for operators inspecting the volume; GUI must be rebuilt if this changes
# and differs from the VITE_API_TOKEN baked into the gui image.
printf '%s\n' "${TOKEN}" > "${TOKEN_FILE}"

CLASSPATH="/opt/veyrion/classes"
for jar in /opt/veyrion/lib/*.jar; do
  CLASSPATH="${CLASSPATH}:${jar}"
done

echo "Veyrion Control Plane root=${ROOT} db=${DB} bind=${BIND} port=${PORT}"
echo "Mutation token file: ${TOKEN_FILE} (loopback / local Compose only; not production auth)"
echo "TRUSTED_DOCKER worker is not started in this container; use host sandbox-pack for dynamic probes."

exec java -cp "${CLASSPATH}" com.aq.jvmsentinel.deploy.ComposeControlPlaneMain \
  --root "${ROOT}" \
  --database "${DB}" \
  --bind "${BIND}" \
  --port "${PORT}" \
  --token "${TOKEN}"

# syntax=docker/dockerfile:1.7
# Local Compose image for Control Plane + static GUI.
# Not a production hardened sandbox; TRUSTED_DOCKER / VERIFIED are not enabled here.

FROM maven:3.9-eclipse-temurin-17 AS cp-build
WORKDIR /workspace
COPY pom.xml ./
COPY src ./src
COPY deploy/java ./deploy/java
RUN --mount=type=cache,target=/root/.m2 \
    mvn --batch-mode --no-transfer-progress -DskipTests package \
    && mvn --batch-mode --no-transfer-progress dependency:build-classpath \
         -Dmdep.outputFile=/tmp/runtime-classpath.txt \
    && mkdir -p /out/classes /out/lib \
    && cp -a target/classes/. /out/classes/ \
    && IFS=':' ; for jar in $(cat /tmp/runtime-classpath.txt); do \
         if [ -f "$jar" ]; then cp -a "$jar" /out/lib/; fi; \
       done \
    && CP="/out/classes" \
    && for jar in /out/lib/*.jar; do CP="$CP:$jar"; done \
    && javac --release 17 -cp "$CP" -d /out/classes \
         deploy/java/com/aq/jvmsentinel/deploy/ComposeControlPlaneMain.java

FROM node:22-bookworm-slim AS fe-build
WORKDIR /frontend
ARG VITE_API_TOKEN=local-demo
ENV VITE_DEMO_MODE=false \
    VITE_API_BASE_URL=/api/v1 \
    VITE_API_TOKEN=${VITE_API_TOKEN}
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM eclipse-temurin:17-jre-jammy AS control-plane
WORKDIR /opt/veyrion
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/veyrion/classes /opt/veyrion/lib /data/artifacts/.veyrion
COPY --from=cp-build /out/classes /opt/veyrion/classes
COPY --from=cp-build /out/lib /opt/veyrion/lib
COPY deploy/entrypoint.sh /opt/veyrion/entrypoint.sh
RUN chmod 755 /opt/veyrion/entrypoint.sh
ENV VEYRION_ARTIFACT_ROOT=/data/artifacts \
    VEYRION_BIND=0.0.0.0 \
    VEYRION_PORT=18080
EXPOSE 18080
VOLUME ["/data/artifacts"]
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD curl -fsS http://127.0.0.1:18080/api/v1/health >/dev/null || exit 1
ENTRYPOINT ["/opt/veyrion/entrypoint.sh"]

FROM nginx:1.27-alpine AS gui
COPY --from=fe-build /frontend/dist /usr/share/nginx/html
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80

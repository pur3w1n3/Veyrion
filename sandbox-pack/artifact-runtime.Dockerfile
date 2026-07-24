# syntax=docker/dockerfile:1.7
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /workspace

COPY agent/pom.xml agent/pom.xml
COPY agent/src agent/src
RUN --mount=type=cache,target=/root/.m2 \
    mvn -f agent/pom.xml --batch-mode --no-transfer-progress package

FROM eclipse-temurin:17-jre
RUN mkdir -p /opt/veyrion/agent /opt/veyrion/artifact /tmp/veyrion-trace /sandbox \
    && chown -R 65532:65532 /tmp/veyrion-trace /sandbox
COPY --from=build /workspace/agent/target/veyrion-jvm-agent-0.1.0-SNAPSHOT.jar \
    /opt/veyrion/agent/veyrion-agent.jar

USER 65532:65532
WORKDIR /sandbox
ENTRYPOINT ["/bin/sh", "-c", "exec sleep infinity"]

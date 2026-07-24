# syntax=docker/dockerfile:1.7
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /workspace

COPY agent/pom.xml agent/pom.xml
COPY agent/src agent/src
RUN --mount=type=cache,target=/root/.m2 \
    mvn -f agent/pom.xml --batch-mode --no-transfer-progress install

COPY fixtures/http-entry/pom.xml fixtures/http-entry/pom.xml
COPY fixtures/http-entry/src fixtures/http-entry/src
RUN --mount=type=cache,target=/root/.m2 \
    mvn -f fixtures/http-entry/pom.xml --batch-mode --no-transfer-progress package

FROM eclipse-temurin:17-jre
RUN mkdir -p /opt/veyrion/agent /opt/veyrion/fixture /tmp/veyrion-trace \
    && chown -R 65532:65532 /tmp/veyrion-trace
COPY --from=build /workspace/agent/target/veyrion-jvm-agent-0.1.0-SNAPSHOT.jar \
    /opt/veyrion/agent/veyrion-agent.jar
COPY --from=build /workspace/fixtures/http-entry/target/fixture.jar \
    /opt/veyrion/fixture/fixture.jar

USER 65532:65532
ENTRYPOINT ["java","-Dveyrion.sandbox.traceDir=/tmp/veyrion-trace","-Dveyrion.sandbox.traceDir.authorized=true","-javaagent:/opt/veyrion/agent/veyrion-agent.jar","-cp","/opt/veyrion/fixture/fixture.jar","com.aq.jvmsentinel.fixture.HttpEntryFixture"]

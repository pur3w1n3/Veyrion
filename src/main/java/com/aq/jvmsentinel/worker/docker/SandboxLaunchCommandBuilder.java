package com.aq.jvmsentinel.worker.docker;

import com.aq.jvmsentinel.analysis.experiment.GuardSurfaceCatalog;
import com.aq.jvmsentinel.worker.ExternalArtifactPaths;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.aq.jvmsentinel.worker.ResourceBudget;
import com.aq.jvmsentinel.worker.agent.AgentTraceReader;
import com.aq.jvmsentinel.worker.probe.ProbeCommandBuilder;

import java.util.List;

/**
 * 断网 Docker 沙箱内启动应用 JAR 的固定 shell 命令构建。
 */
public final class SandboxLaunchCommandBuilder {
    private SandboxLaunchCommandBuilder() { }

    public static String fixedCommand(ResourceBudget budget,
                                      ExternalArtifactTaskExecutor.ArtifactRegistration registration) {
        long maxBytes = AgentTraceReader.agentTraceBudget(budget, registration.probePlan().size());
        // ~128 字节/事件（XSS hop 过滤后）；为 FORCED PathTrace 留余量。
        long maxEvents = Math.max(1, Math.min(100_000, maxBytes / 128));
        long runSeconds = Math.max(1, budget.maxWallClockSeconds() - 15);
        String worldPackMode = registration.worldPackDependencyMode();
        boolean mockDependencies = !"OBSERVE_FAIL".equalsIgnoreCase(worldPackMode);
        // 应用就绪与任务 wall clock 分离；HTTP 就绪后剩余预算用于探针与轨迹采集。
        long startupLimitSeconds = registration.sizeBytes() >= 80L * 1024 * 1024 ? 180
                : registration.sizeBytes() >= 20L * 1024 * 1024 ? 120 : 90;
        long startupSeconds = Math.min(runSeconds, startupLimitSeconds);
        String businessProbes = ProbeCommandBuilder.batchProbeStep(registration.probePlan());
        if (businessProbes.isBlank()) {
            businessProbes = ProbeCommandBuilder.batchProbeStep(List.of(
                    new ExternalArtifactTaskExecutor.ProbeTarget(
                            registration.probeMethod(), registration.probeRoute())));
        }
        // 不强制 server.port/address：JAR 保留自身监听配置。
        // 就绪用 WaitHttpReady（进程 LISTEN → HTTP 分类），避免脆弱 shell 引号。
        boolean mysqlConnector = ArtifactJarInspection.containsMysqlConnector(registration.path());
        // JDBC URL 用 /bin/sh 单引号：未引号的 query 中 '&' 会把 java 进程放到后台，
        // 后续 --spring.* 会变成独立 shell 命令（exit 70）。
        String datasource = mysqlConnector
                ? SandboxShellSupport.shellSingleQuoted(
                        "jdbc:mysql://127.0.0.1:3306/veyrion?connectTimeout=1000&socketTimeout=1000&useSSL=false")
                : "jdbc:veyrion-mock:mem:veyrion";
        String driver = mysqlConnector ? "" : " --spring.datasource.driver-class-name="
                + "com.aq.jvmsentinel.instrumentation.mock.VeyrionMockDriver";
        ExternalArtifactTaskExecutor.ForcedGuardAllowlist forcedGuards =
                ArtifactJarInspection.forcedGuardAllowlist(registration.path());
        String forcedGuardTypes = forcedGuards.typeNamesCsv();
        return SandboxShellSupport.writeProgress(
                "启动应用 JAR（保留制品自身端口；javaagent hook + 协议级依赖替身；容器断网）"
                + (forcedGuards.truncated() ? "；" + GuardSurfaceCatalog.GAP_CATALOG_TRUNCATED : ""))
                + "; java"
                + " -Dveyrion.sandbox.traceDir=" + ExternalArtifactPaths.TRACE_DIRECTORY
                + " -Dveyrion.sandbox.traceDir.authorized=true"
                + " -Dveyrion.sandbox.docker=true"
                + " -Dveyrion.worldPack.dependencyMode=" + worldPackMode
                + " -Dveyrion.sandbox.dependencyMock=" + mockDependencies
                + " -Dveyrion.coverage.enabled=true"
                + (forcedGuardTypes.isEmpty()
                ? "" : " -Dveyrion.sandbox.forcedGuardTypeNames="
                + SandboxShellSupport.shellSingleQuoted(forcedGuardTypes))
                + (forcedGuards.truncated()
                ? " -Dveyrion.sandbox.forcedGuardCatalogTruncated=true" : "")
                // 应用临时目录避开 trace tmpfs，以便 probe-events.jsonl 仍可写入。
                + " -Djava.io.tmpdir=/tmp"
                // Quartz AUTO 用 hostname；deny-all Docker 常无法解析
                // （"Couldn't get host name" → "Cannot run without an instance id"）。
                // 固定字面 id（非 AUTO / SYS_PROP）。
                + " -Dorg.quartz.scheduler.instanceName=veyrion-sandbox"
                + " -Dorg.quartz.scheduler.instanceId=veyrion-sandbox"
                // World Pack 模式仅 -D，以便旧 digest 钉死的 runtime Agent JAR 仍兼容。
                + " -javaagent:" + ExternalArtifactPaths.AGENT_PATH + "=maxBytes=" + maxBytes
                + ",maxEvents=" + maxEvents
                + ",dependencyMock=" + mockDependencies
                + ",veyrion.coverage.enabled=true"
                + (registration.classPrefix().isEmpty()
                ? "" : ",classPrefix=" + registration.classPrefix())
                + " -jar " + ExternalArtifactPaths.ARTIFACT_PATH
                // fail-open 连接池 + 协议 mock URL，使 deny-all JAR 可在 loopback 绑定供探针。
                + " --spring.main.lazy-initialization=true"
                + (mockDependencies
                ? " --spring.datasource.url=" + datasource
                + driver
                + " --spring.datasource.hikari.initialization-fail-timeout=-1"
                + " --spring.datasource.hikari.connection-timeout=1000"
                + " --spring.datasource.druid.initial-size=0"
                + " --spring.datasource.druid.min-idle=0"
                + " --spring.datasource.druid.max-wait=1000"
                + " --spring.datasource.druid.fail-fast=false"
                + " --spring.datasource.druid.connection-error-retry-attempts=0"
                + " --spring.datasource.druid.break-after-acquire-failure=true"
                + " --spring.datasource.druid.test-while-idle=false"
                + " --spring.redis.host=127.0.0.1"
                + " --spring.redis.port=6379"
                + " --spring.redis.timeout=500ms"
                + " --spring.data.redis.timeout=500ms"
                + " --management.health.redis.enabled=false"
                : "")
                + " --spring.flyway.enabled=false"
                + " --spring.liquibase.enabled=false"
                + " --spring.sql.init.mode=never"
                + " --spring.jpa.hibernate.ddl-auto=none"
                + " --spring.data.redis.repositories.enabled=false"
                + " --spring.quartz.auto-startup=false"
                + " --spring.quartz.job-store-type=memory"
                + " --spring.quartz.overwrite-existing-jobs=false"
                + " --spring.quartz.properties.org.quartz.scheduler.instanceName=veyrion-sandbox"
                + " --spring.quartz.properties.org.quartz.scheduler.instanceId=veyrion-sandbox"
                + " --spring.quartz.properties.org.quartz.jobStore.class="
                + "org.quartz.simpl.RAMJobStore"
                + " --spring.quartz.properties.org.quartz.jobStore.isClustered=false"
                + " > " + ExternalArtifactPaths.TRACE_DIRECTORY + "/application.log 2>&1"
                + " & APP_PID=$!; elapsed=0; probe_status=1; probe_jvm_status=not-run; PROBE_JVM_OK=0; HTTP_PORT="
                + "; rm -f " + ExternalArtifactPaths.TRACE_DIRECTORY + "/http-port.txt "
                + ExternalArtifactPaths.TRACE_DIRECTORY + "/listen-ports.txt "
                + ExternalArtifactPaths.TRACE_DIRECTORY + "/http-port.stdout "
                + ExternalArtifactPaths.TRACE_DIRECTORY + "/wait-http-ready.err "
                + ExternalArtifactPaths.PROBE_TRACE_FILE + " " + ExternalArtifactPaths.PROBE_STATUS_FILE
                + "; " + SandboxShellSupport.writeProgress("等待应用就绪（分析进程 LISTEN 端口）")
                + "; while kill -0 \"$APP_PID\" 2>/dev/null"
                + " && [ \"$elapsed\" -lt " + startupSeconds + " ]"
                + "; do"
                + " if java -Xmx64m -XX:MaxMetaspaceSize=64m -Dveyrion.sandbox.traceDir="
                + ExternalArtifactPaths.TRACE_DIRECTORY
                + " -cp " + ExternalArtifactPaths.AGENT_PATH
                + " com.aq.jvmsentinel.agent.WaitHttpReady \"$APP_PID\" "
                + ExternalArtifactPaths.TRACE_DIRECTORY
                + " > " + ExternalArtifactPaths.TRACE_DIRECTORY + "/http-port.stdout 2>> "
                + ExternalArtifactPaths.TRACE_DIRECTORY + "/wait-http-ready.err"
                + "; then HTTP_PORT=$(cat " + ExternalArtifactPaths.TRACE_DIRECTORY
                + "/http-port.stdout 2>/dev/null | tr -d '\\r\\n');"
                + " break; fi"
                + "; sleep 2; elapsed=$((elapsed+2)); done"
                + "; if [ -z \"$HTTP_PORT\" ] && [ -f " + ExternalArtifactPaths.TRACE_DIRECTORY
                + "/http-port.txt ]"
                + "; then HTTP_PORT=$(cat " + ExternalArtifactPaths.TRACE_DIRECTORY
                + "/http-port.txt | tr -d '\\r\\n'); fi"
                + "; case \"$HTTP_PORT\" in ''|*[!0-9]*|3306|6379|5432|27017|11211|9200|5672|61616|9092) HTTP_PORT= ;; esac"
                + "; if kill -0 \"$APP_PID\" 2>/dev/null && [ -n \"$HTTP_PORT\" ]"
                + "; then probe_status=0"
                + "; printf '应用已就绪，HTTP 端口 %s，开始业务入口探测\\n' \"$HTTP_PORT\" > "
                + ExternalArtifactPaths.TRACE_DIRECTORY + "/progress.txt"
                + "; " + businessProbes
                + "; fi"
                + "; if [ \"$probe_status\" -eq 0 ] && [ \"$PROBE_JVM_OK\" -eq 1 ]; then "
                + "printf '%s\\n' \"$HTTP_PORT\" > " + ExternalArtifactPaths.TRACE_DIRECTORY + "/http-port.txt"
                + "; " + SandboxShellSupport.writeProgress("探测完成，保留应用进程供 PATH/TRIAGE 复用")
                + "; exit 0"
                + "; elif [ \"$probe_status\" -eq 0 ]; then "
                + "printf 'HTTP 端口已就绪但批量探针失败（退出码 %s），停止应用进程\\n' "
                + "\"$probe_jvm_status\" > " + ExternalArtifactPaths.TRACE_DIRECTORY + "/progress.txt"
                + "; else " + SandboxShellSupport.writeProgress("就绪超时，停止应用进程")
                + "; fi"
                + "; if kill -0 \"$APP_PID\" 2>/dev/null; then "
                + "kill -TERM \"$APP_PID\""
                + "; grace=0; while kill -0 \"$APP_PID\" 2>/dev/null && [ \"$grace\" -lt 10 ]"
                + "; do sleep 1; grace=$((grace+1)); done"
                + "; if kill -0 \"$APP_PID\" 2>/dev/null; then kill -KILL \"$APP_PID\"; fi"
                + "; wait \"$APP_PID\" 2>/dev/null || true"
                + "; if [ \"$probe_status\" -ne 0 ]; then exit 70"
                + "; elif [ \"$PROBE_JVM_OK\" -ne 1 ]; then exit 71"
                + "; else exit 0; fi"
                + "; else wait \"$APP_PID\"; app_status=$?"
                + "; if [ \"$probe_status\" -ne 0 ]; then exit 70"
                + "; elif [ \"$PROBE_JVM_OK\" -ne 1 ]; then exit 71"
                + "; else exit \"$app_status\"; fi; fi";
    }
}

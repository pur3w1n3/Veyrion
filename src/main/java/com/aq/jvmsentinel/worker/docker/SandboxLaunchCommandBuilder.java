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
    /**
     * 与 agent {@code AgentConfig} 的 maxEvents 上限同步（当前 500_000）。
     * 下发值超出该区间时 premain 会直接失败，应用 HTTP 永不就绪（exit 70）。
     */
    public static final long AGENT_MAX_EVENTS = 500_000L;
    /** 与 agent {@code AgentConfig} 的 maxEvents 下限同步。 */
    public static final long AGENT_MIN_EVENTS = 1L;
    /** 按探针数抬升轨迹事件预算的下限系数（XSS hop 过滤后约 96 字节/事件）。 */
    public static final long EVENTS_PER_PROBE = 2_500L;
    /** 事件体积粗估；与 {@link #resolveAgentMaxEvents} / {@link #resolveTraceBytesBudget} 共用。 */
    public static final long BYTES_PER_EVENT_ESTIMATE = 96L;

    private SandboxLaunchCommandBuilder() { }

    /**
     * 计算下发给 javaagent 的 maxEvents：按探针抬升，但必须钳在 agent 合法区间内。
     */
    public static long resolveAgentMaxEvents(int probeCount, long maxBytes) {
        int probes = Math.max(1, probeCount);
        long fromBytes = Math.max(AGENT_MIN_EVENTS, maxBytes / BYTES_PER_EVENT_ESTIMATE);
        long raised = Math.max(probes * EVENTS_PER_PROBE, Math.min(AGENT_MAX_EVENTS, fromBytes));
        return Math.max(AGENT_MIN_EVENTS, Math.min(AGENT_MAX_EVENTS, raised));
    }

    /**
     * 动态任务轨迹字节预算：按探针事件下限抬升，钳在 {@link ExternalArtifactPaths#MAX_TRACE_BYTES}。
     * 避免「maxEvents 抬到 50 万但 maxTraceBytes 仍卡 16MiB」导致字节侧先饿死。
     */
    public static long resolveTraceBytesBudget(int probeCount, long artifactSizeBytes) {
        int probes = Math.max(1, Math.min(ExternalArtifactPaths.MAX_PROBE_PLAN_ENTRIES, probeCount));
        long sizeFloor = artifactSizeBytes >= 20L * 1024 * 1024 ? 4L * 1024 * 1024 : 512L * 1024;
        // 复用沙箱 PATH 探针需在 agent 轨迹旁再写完整 probe-events；按条目保留余量。
        long probeFloor = 1024L * 1024
                + probes * ExternalArtifactPaths.PROBE_TRACE_BYTES_PER_ENTRY * 2L;
        long eventsFloor = probes * EVENTS_PER_PROBE * BYTES_PER_EVENT_ESTIMATE;
        return Math.min(ExternalArtifactPaths.MAX_TRACE_BYTES,
                Math.max(sizeFloor, Math.max(probeFloor, eventsFloor)));
    }

    /**
     * 轨迹目录 tmpfs：{@code maxTraceBytes + TMPFS_TRACE_HEADROOM_BYTES}，钳在
     * {@link ExternalArtifactPaths#MAX_TMPFS_BYTES}。
     */
    public static long resolveTraceTmpfsBytes(long maxTraceBytes) {
        long trace = Math.min(ExternalArtifactPaths.MAX_TRACE_BYTES, Math.max(0L, maxTraceBytes));
        long needed = trace + ExternalArtifactPaths.TMPFS_TRACE_HEADROOM_BYTES;
        return Math.min(ExternalArtifactPaths.MAX_TMPFS_BYTES,
                Math.max(ExternalArtifactPaths.TMPFS_TRACE_HEADROOM_BYTES, needed));
    }

    /**
     * {@code /tmp} tmpfs：不低于 {@link ExternalArtifactPaths#MIN_TMP_TMPFS_BYTES}，
     * 且不低于轨迹侧 tmpfs，避免应用临时目录比轨迹挂载更早 ENOSPC。
     */
    public static long resolveTmpTmpfsBytes(long traceTmpfsBytes) {
        long traceSide = Math.max(0L, traceTmpfsBytes);
        return Math.max(ExternalArtifactPaths.MIN_TMP_TMPFS_BYTES, traceSide);
    }

    /**
     * 动态任务 disk 预算下限：至少覆盖轨迹 tmpfs（含 headroom），并保留历史 64MiB 地板。
     */
    public static long resolveDiskBytesBudget(long maxTraceBytes) {
        long floor = 64L * 1024 * 1024;
        return Math.min(ExternalArtifactPaths.MAX_DISK_BYTES,
                Math.max(floor, resolveTraceTmpfsBytes(maxTraceBytes)));
    }

    public static String fixedCommand(ResourceBudget budget,
                                      ExternalArtifactTaskExecutor.ArtifactRegistration registration) {
        int probeCount = Math.max(1, registration.probePlan().size());
        long maxBytes = AgentTraceReader.agentTraceBudget(budget, probeCount);
        // ~96 字节/事件（XSS hop 过滤后）；按探针数抬高下限，降低后半程探针被洪泛饿死概率。
        // 抬升后仍钳制到 agent 合法区间，避免 maxEvents 越界导致 premain 崩掉。
        long maxEvents = resolveAgentMaxEvents(probeCount, maxBytes);
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
                + ExternalArtifactPaths.TRACE_DIRECTORY + "/http-context-path.txt "
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

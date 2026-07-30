package com.aq.jvmsentinel.worker.probe;

import com.aq.jvmsentinel.worker.ExternalArtifactPaths;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.aq.jvmsentinel.worker.docker.SandboxShellSupport;

import java.util.List;

/**
 * 容器内 loopback HTTP 批量探针 shell 步骤构建。
 */
public final class ProbeCommandBuilder {
    private ProbeCommandBuilder() { }

    /** 单 JVM 读取整个计划文件，使数百入口仍落在 wall clock 内。 */
    public static String batchProbeStep(List<ExternalArtifactTaskExecutor.ProbeTarget> targets) {
        int count = targets == null ? 0 : targets.size();
        // 有界堆以便探针与大 Blade 应用并存；不吞掉 JVM 崩溃。
        return SandboxShellSupport.writeProgress("开始批量探测 " + count + " 个 HTTP 入口（单 JVM）")
                + "; printf 'probe selected http port: %s\\n' \"$HTTP_PORT\" >&2"
                + "; case \"$HTTP_PORT\" in ''|*[!0-9]*|3306|6379|5432|27017|11211|9200|5672|61616|9092)"
                + " probe_jvm_status=64;"
                + " printf 'invalid or dependency HTTP_PORT for probe: %s\\n' \"$HTTP_PORT\" >&2 ;;"
                + " *) java -Xmx64m -XX:MaxMetaspaceSize=64m -Dveyrion.sandbox.traceDir="
                + ExternalArtifactPaths.TRACE_DIRECTORY
                + " -Dveyrion.loopbackProbe.port=\"$HTTP_PORT\""
                + " -cp " + ExternalArtifactPaths.AGENT_PATH
                + " com.aq.jvmsentinel.agent.LoopbackHttpProbe --batch "
                + ExternalArtifactPaths.TRACE_DIRECTORY + "/probe-plan.txt \"$HTTP_PORT\""
                + "; probe_jvm_status=$? ;; esac"
                + "; printf 'probe_jvm_status=%s\\n' \"$probe_jvm_status\" > "
                + ExternalArtifactPaths.PROBE_STATUS_FILE
                // 0=成功；2=全部 HTTP 失败但仍有证据。4=证据写失败（tmpfs/IO）不可当成功。
                + "; if [ \"$probe_jvm_status\" -eq 0 ] || [ \"$probe_jvm_status\" -eq 2 ]"
                + "; then PROBE_JVM_OK=1; fi";
    }
}

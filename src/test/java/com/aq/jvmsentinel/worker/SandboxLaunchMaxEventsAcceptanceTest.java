package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.worker.docker.SandboxLaunchCommandBuilder;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 沙箱 javaagent maxEvents 必须落在 agent 合法区间，避免 premain 因越界直接失败；
 * 轨迹字节预算须随探针抬升，避免「事件上限抬了、字节仍卡 16MiB」。
 */
public final class SandboxLaunchMaxEventsAcceptanceTest {
    private static final Pattern MAX_EVENTS = Pattern.compile("maxEvents=(\\d+)");
    private static final ResourceBudget BUDGET = new ResourceBudget(
            180, 60_000, 512L * 1024 * 1024, 64L * 1024 * 1024, 48L * 1024 * 1024);

    private SandboxLaunchMaxEventsAcceptanceTest() { }

    public static void main(String[] args) throws Exception {
        check(SandboxLaunchCommandBuilder.AGENT_MAX_EVENTS == 500_000L,
                "control-plane AGENT_MAX_EVENTS must stay synced with agent MAX_MAX_EVENTS");
        check(SandboxLaunchCommandBuilder.AGENT_MIN_EVENTS == 1L,
                "control-plane AGENT_MIN_EVENTS must stay synced with agent MIN_MAX_EVENTS");

        // 200 探针 × 2500 = 500000，恰为新上界。
        long atCap = SandboxLaunchCommandBuilder.resolveAgentMaxEvents(200, 48L * 1024 * 1024);
        check(atCap == 500_000L, "200 probes * 2500 must remain exactly at agent max; got " + atCap);

        // 抬升后仍合法：201 * 2500 = 502500 在修复前会越界（若上界仍 100k）或需钳制。
        long raised = SandboxLaunchCommandBuilder.resolveAgentMaxEvents(201, 48L * 1024 * 1024);
        check(raised == SandboxLaunchCommandBuilder.AGENT_MAX_EVENTS,
                "probe-raised maxEvents must clamp to agent max; got " + raised);

        // 字节侧偏紧时，探针地板 40*2500=100000 仍生效（fromBytes 更小则取探针地板）。
        long forty = SandboxLaunchCommandBuilder.resolveAgentMaxEvents(40, 50_000L * 96L);
        check(forty == 100_000L, "40 probes * 2500 floor must win over smaller fromBytes; got " + forty);
        // 字节侧很宽时，fromBytes 可把 maxEvents 抬到 AGENT_MAX（与探针数无关的旧行为）。
        long fortyWide = SandboxLaunchCommandBuilder.resolveAgentMaxEvents(40, 48L * 1024 * 1024);
        check(fortyWide == SandboxLaunchCommandBuilder.AGENT_MAX_EVENTS,
                "wide maxBytes may raise to agent max; got " + fortyWide);

        long small = SandboxLaunchCommandBuilder.resolveAgentMaxEvents(1, 96L * 50);
        check(small >= SandboxLaunchCommandBuilder.AGENT_MIN_EVENTS
                        && small <= SandboxLaunchCommandBuilder.AGENT_MAX_EVENTS,
                "small budget maxEvents must stay inside agent limits; got " + small);
        check(small == Math.max(2_500L, 50L),
                "single-probe floor should apply when byte-derived is smaller; got " + small);

        long maxPlan = SandboxLaunchCommandBuilder.resolveAgentMaxEvents(
                ExternalArtifactPaths.MAX_PROBE_PLAN_ENTRIES, ExternalArtifactPaths.MAX_TRACE_BYTES);
        check(maxPlan == SandboxLaunchCommandBuilder.AGENT_MAX_EVENTS,
                "max probe plan must still clamp; got " + maxPlan);

        long tooSmallBytes = SandboxLaunchCommandBuilder.resolveAgentMaxEvents(1, 0);
        check(tooSmallBytes == SandboxLaunchCommandBuilder.EVENTS_PER_PROBE,
                "zero maxBytes must still apply single-probe floor then stay legal; got "
                        + tooSmallBytes);

        long trace200 = SandboxLaunchCommandBuilder.resolveTraceBytesBudget(200, 1_000_000);
        check(trace200 == 200L * 2_500L * 96L,
                "200-probe trace budget must cover events floor; got " + trace200);
        long trace512 = SandboxLaunchCommandBuilder.resolveTraceBytesBudget(512, 80L * 1024 * 1024);
        check(trace512 == ExternalArtifactPaths.MAX_TRACE_BYTES,
                "full probe plan must clamp trace bytes to MAX_TRACE_BYTES; got " + trace512);
        long traceSmall = SandboxLaunchCommandBuilder.resolveTraceBytesBudget(1, 1_000);
        check(traceSmall >= 512L * 1024, "tiny artifact still keeps 512KiB floor; got " + traceSmall);

        Path jar = Files.createTempFile("veyrion-maxevents-", ".jar");
        try {
            Files.write(jar, new byte[]{'P', 'K', 3, 4});
            List<ExternalArtifactTaskExecutor.ProbeTarget> probes = new ArrayList<>();
            for (int i = 0; i < 220; i++) {
                probes.add(new ExternalArtifactTaskExecutor.ProbeTarget("GET", "/p" + i));
            }
            ExternalArtifactTaskExecutor.ArtifactRegistration registration =
                    new ExternalArtifactTaskExecutor.ArtifactRegistration(
                            "project-1", "a".repeat(64), jar, Files.size(jar), true,
                            "GET", "/p0", "", probes, "MOCK_CONTINUE");
            String command = SandboxLaunchCommandBuilder.fixedCommand(BUDGET, registration);
            Matcher matcher = MAX_EVENTS.matcher(command);
            check(matcher.find(), "fixedCommand must emit maxEvents");
            long emitted = Long.parseLong(matcher.group(1));
            check(emitted >= SandboxLaunchCommandBuilder.AGENT_MIN_EVENTS
                            && emitted <= SandboxLaunchCommandBuilder.AGENT_MAX_EVENTS,
                    "fixedCommand maxEvents outside agent limits: " + emitted);
            check(emitted == SandboxLaunchCommandBuilder.AGENT_MAX_EVENTS,
                    "220-probe plan must emit clamped agent max; got " + emitted);
            check(!matcher.find(), "fixedCommand must emit maxEvents exactly once");
        } finally {
            Files.deleteIfExists(jar);
        }

        System.out.println("SandboxLaunchMaxEventsAcceptanceTest: PASS");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}

package com.aq.jvmsentinel.harness;

import java.util.List;
import java.util.Objects;

/**
 * 固定 Worker 侧 javac 请求。唯一 classpath 条目为 digest 校验过的原始 JAR；
 * decompiler 输出目录不能由本 contract 表示。
 */
public record HarnessCompilationRequest(int schemaVersion, String artifactDigest,
                                        String originalJarPath, boolean originalJarReadOnly,
                                        String generatedSourcePath, String outputDirectory,
                                        long maxWallClockMillis, long maxOutputBytes) {
    public static final int SCHEMA_VERSION = 1;
    public static final String ORIGINAL_JAR = "/input/original.jar";
    public static final String SOURCE = "/work/generated/VeyrionHarness.java";
    public static final String OUTPUT = "/output/harness-classes";

    public HarnessCompilationRequest {
        if (schemaVersion != SCHEMA_VERSION) throw new IllegalArgumentException("unsupported schemaVersion");
        Objects.requireNonNull(artifactDigest, "artifactDigest");
        if (!artifactDigest.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("artifactDigest must be a lowercase SHA-256");
        }
        if (!ORIGINAL_JAR.equals(originalJarPath) || !originalJarReadOnly) {
            throw new IllegalArgumentException("classpath input must be the fixed read-only original JAR");
        }
        if (!SOURCE.equals(generatedSourcePath) || !OUTPUT.equals(outputDirectory)) {
            throw new IllegalArgumentException("harness paths are fixed by Worker policy");
        }
        if (maxWallClockMillis <= 0 || maxWallClockMillis > 300_000
                || maxOutputBytes <= 0 || maxOutputBytes > 64L * 1024 * 1024) {
            throw new IllegalArgumentException("harness compilation budget is outside policy");
        }
    }

    public void verifyPlan(HarnessPlan plan) {
        Objects.requireNonNull(plan, "plan");
        if (!artifactDigest.equals(plan.target().artifactDigest())) {
            throw new SecurityException("HarnessPlan artifact digest mismatch");
        }
    }

    /** 参数由隔离 Worker 直接传给 process API，永不传给 shell。 */
    public List<String> javacArguments(String verifiedOriginalJarDigest) {
        if (!artifactDigest.equals(verifiedOriginalJarDigest)) {
            throw new SecurityException("original JAR digest mismatch");
        }
        return List.of("/opt/java/bin/javac", "--release", "17", "-proc:none",
                "-classpath", ORIGINAL_JAR, "-d", OUTPUT, SOURCE);
    }
}

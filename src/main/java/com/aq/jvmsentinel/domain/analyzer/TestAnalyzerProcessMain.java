package com.aq.jvmsentinel.domain.analyzer;

import com.aq.jvmsentinel.domain.ir.StableNodeIds;
import com.aq.jvmsentinel.domain.universe.CoverageGap;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 独立进程 Test Analyzer 入口（P1-07）。
 *
 * <p>Started via {@link ProcessBuilder}; writes a minimal staged-IR envelope to the path in
 * {@code args[0]}. Has no Control Plane store, AI tools, or Worker privileges — only emits
 * 版本化 IR chunk，供父进程经 {@link AnalyzerIngress} 摄入。
 *
 * <p>Args: {@code <outPath> <projectId> <artifactDigest> <scanId> <analysisId> <policyDigest>
 * <submissionId>}
 */
public final class TestAnalyzerProcessMain {
    public static final String ANALYZER_ID = "test-analyzer-process";
    public static final String ANALYZER_VERSION = "0.1.0";
    public static final String LANGUAGE = "testlang";
    public static final String MARKER = "VEYRION_TEST_ANALYZER_PROCESS_OK";

    private TestAnalyzerProcessMain() {
    }

    public static void main(String[] args) throws Exception {
        if (args == null || args.length < 7) {
            System.err.println("usage: TestAnalyzerProcessMain <outPath> <projectId> "
                    + "<artifactDigest> <scanId> <analysisId> <policyDigest> <submissionId>");
            System.exit(2);
        }
        Path out = Path.of(args[0]);
        AnalyzerScope scope = new AnalyzerScope(args[1], args[2], args[3], args[4]);
        String policyDigest = AnalyzerContracts.digest(args[5], "policyDigest");
        String submissionId = AnalyzerContracts.id(args[6], "submissionId");
        Set<AnalyzerCapability> capabilities = EnumSet.of(
                AnalyzerCapability.PROGRAM_IR,
                AnalyzerCapability.ENTRY_SURFACE,
                AnalyzerCapability.COVERAGE_GAP,
                AnalyzerCapability.DIAGNOSTIC);

        List<IrChunk> chunks = minimalChunks(scope);
        IrChunkManifest manifest = IrChunkManifest.of(chunks);
        AnalyzerSubmission submission = new AnalyzerSubmission(
                AnalyzerContracts.SCHEMA_VERSION,
                submissionId,
                scope,
                scope.artifactDigest(),
                policyDigest,
                capabilities,
                manifest,
                List.of(AnalyzerDiagnostic.info("ANALYSIS_COMPLETE", "subprocess test analyzer ok")),
                List.of(new AnalyzerCoverageGapDto(
                        "gap-process-unresolved-1",
                        CoverageGap.KIND_UNRESOLVED_CALL,
                        "call to unknown.symbol",
                        "STATIC_LIMIT",
                        "ev-gap-process-1")),
                new AnalyzerResourceUsage(chunks.size(), manifest.totalPayloadBytes(), 20, 2),
                AnalyzerTerminalState.SUCCESS,
                "COMPLETED",
                null);

        StringBuilder json = new StringBuilder(2048);
        json.append("{\n");
        json.append("  \"marker\": \"").append(MARKER).append("\",\n");
        json.append("  \"analyzerId\": \"").append(ANALYZER_ID).append("\",\n");
        json.append("  \"analyzerVersion\": \"").append(ANALYZER_VERSION).append("\",\n");
        json.append("  \"language\": \"").append(LANGUAGE).append("\",\n");
        json.append("  \"pid\": ").append(ProcessHandle.current().pid()).append(",\n");
        json.append("  \"artifactDigest\": \"").append(scope.artifactDigest()).append("\",\n");
        json.append("  \"policyDigest\": \"").append(policyDigest).append("\",\n");
        json.append("  \"submissionId\": \"").append(submission.submissionId()).append("\",\n");
        json.append("  \"fingerprint\": \"").append(submission.fingerprint()).append("\",\n");
        json.append("  \"capabilities\": [")
                .append(capabilities.stream().map(c -> "\"" + c.name() + "\"")
                        .collect(Collectors.joining(", ")))
                .append("],\n");
        json.append("  \"scope\": ").append(mapToJson(scope.toMap())).append(",\n");
        json.append("  \"chunks\": [\n");
        for (int i = 0; i < chunks.size(); i++) {
            if (i > 0) {
                json.append(",\n");
            }
            json.append("    ").append(mapToJson(chunks.get(i).toMap()));
        }
        json.append("\n  ]\n");
        json.append("}\n");

        Files.createDirectories(out.getParent() == null ? Path.of(".") : out.getParent());
        Files.writeString(out, json.toString(), StandardCharsets.UTF_8);
        System.out.println(MARKER);
    }

    static List<IrChunk> minimalChunks(AnalyzerScope scope) {
        Map<String, Object> program = new LinkedHashMap<>();
        program.put("id", StableNodeIds.programClass("test.ProcessApp"));
        program.put("elementKind", "CLASS");
        program.put("language", LANGUAGE);
        program.put("symbol", "test.ProcessApp");
        program.put("location", "test/ProcessApp.class");

        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("id", StableNodeIds.entry("entry-process-1"));
        entry.put("protocol", "HTTP");
        entry.put("operation", "GET");
        entry.put("address", "/api/process-test");
        entry.put("declaringSymbol", "test.ProcessApp#handle");

        Map<String, Object> gap = new LinkedHashMap<>();
        gap.put("id", "gap-process-unresolved-1");
        gap.put("kind", CoverageGap.KIND_UNRESOLVED_CALL);
        gap.put("detail", "call to unknown.symbol");
        gap.put("stopReason", "STATIC_LIMIT");

        return List.of(
                IrChunk.create(scope, 0, IrChunk.KIND_PROGRAM_NODE, program),
                IrChunk.create(scope, 1, IrChunk.KIND_ENTRY, entry),
                IrChunk.create(scope, 2, IrChunk.KIND_COVERAGE_GAP, gap));
    }

    /** Minimal deterministic JSON for Maps used by this envelope (no Jackson in domain). */
    @SuppressWarnings("unchecked")
    static String mapToJson(Map<String, ?> map) {
        StringBuilder builder = new StringBuilder();
        builder.append('{');
        boolean first = true;
        for (Map.Entry<String, ?> entry : map.entrySet()) {
            if (!first) {
                builder.append(',');
            }
            first = false;
            builder.append('"').append(escape(entry.getKey())).append("\":");
            builder.append(valueToJson(entry.getValue()));
        }
        builder.append('}');
        return builder.toString();
    }

    @SuppressWarnings("unchecked")
    private static String valueToJson(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String text) {
            return "\"" + escape(text) + "\"";
        }
        if (value instanceof Number || value instanceof Boolean) {
            return String.valueOf(value);
        }
        if (value instanceof Map<?, ?> nested) {
            return mapToJson((Map<String, ?>) nested);
        }
        if (value instanceof List<?> list) {
            StringBuilder builder = new StringBuilder();
            builder.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    builder.append(',');
                }
                builder.append(valueToJson(list.get(i)));
            }
            builder.append(']');
            return builder.toString();
        }
        return "\"" + escape(String.valueOf(value)) + "\"";
    }

    private static String escape(String text) {
        return text.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}

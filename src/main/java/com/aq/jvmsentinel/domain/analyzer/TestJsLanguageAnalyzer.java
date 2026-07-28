package com.aq.jvmsentinel.domain.analyzer;

import com.aq.jvmsentinel.domain.ir.StableNodeIds;
import com.aq.jvmsentinel.domain.universe.CoverageGap;

import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Second-language static LanguageAnalyzer stub (JavaScript / ECMAScript).
 *
 * <p>Speaks the out-of-process Analyzer contract and emits non-JVM {@code ProgramNode}
 * fragments. Does not embed a JS parser in the Control Plane and grants no RuntimeAdapter
 * or dynamic-execution rights (ADR-0001).
 */
public final class TestJsLanguageAnalyzer {
    public static final String ANALYZER_ID = "test-js-language-analyzer";
    public static final String ANALYZER_VERSION = "0.1.0";
    public static final String LANGUAGE = "javascript";
    public static final String MEDIA_TYPE = "application/javascript";

    public static final Set<AnalyzerCapability> STATIC_CAPABILITIES = EnumSet.of(
            AnalyzerCapability.PROGRAM_IR,
            AnalyzerCapability.ENTRY_SURFACE,
            AnalyzerCapability.COVERAGE_GAP,
            AnalyzerCapability.DIAGNOSTIC);

    private final AnalyzerScope scope;
    private final String artifactDigest;
    private final String policyDigest;

    public TestJsLanguageAnalyzer(AnalyzerScope scope, String artifactDigest, String policyDigest) {
        this.scope = Objects.requireNonNull(scope, "scope");
        this.artifactDigest = AnalyzerContracts.digest(artifactDigest, "artifactDigest");
        this.policyDigest = AnalyzerContracts.digest(policyDigest, "policyDigest");
        if (!artifactDigest.equals(scope.artifactDigest())) {
            throw new AnalyzerRejectException(AnalyzerRejectReason.ARTIFACT_DIGEST_MISMATCH,
                    "analyzer artifactDigest must match scope");
        }
    }

    public CapabilityNegotiation offer() {
        return new CapabilityNegotiation(
                AnalyzerContracts.SCHEMA_VERSION,
                ANALYZER_ID,
                ANALYZER_VERSION,
                List.of(LANGUAGE),
                List.of(MEDIA_TYPE),
                STATIC_CAPABILITIES,
                AnalyzerSchemaRange.v1Only(),
                artifactDigest,
                policyDigest,
                scope,
                List.of("PROGRAM_IR", "ENTRY_SURFACE", "COVERAGE_GAP"));
    }

    /** Minimal non-JVM IR: module ProgramNode + HTTP EntrySurface + CoverageGap. */
    public List<IrChunk> minimalStaticChunks() {
        Map<String, Object> program = new LinkedHashMap<>();
        program.put("id", "program:module:javascript:routes/users");
        program.put("elementKind", "MODULE");
        program.put("language", LANGUAGE);
        program.put("symbol", "routes/users");
        program.put("location", "src/routes/users.js:12");
        program.put("provenanceKind", "FACT");
        program.put("evidenceRefs", List.of("ev-js-program-1"));
        program.put("extensions", Map.of(
                "javascript", Map.of(
                        "moduleKind", "esm",
                        "exportName", "listUsers",
                        "astKind", "FunctionDeclaration")));

        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("id", StableNodeIds.entry("entry-js-users-get"));
        entry.put("protocol", "HTTP");
        entry.put("operation", "GET");
        entry.put("address", "/api/users");
        entry.put("declaringSymbol", "routes/users#listUsers");

        Map<String, Object> gap = new LinkedHashMap<>();
        gap.put("id", "gap-js-dynamic-import-1");
        gap.put("kind", CoverageGap.KIND_UNRESOLVED_CALL);
        gap.put("detail", "dynamic import() target unresolved");
        gap.put("stopReason", "STATIC_LIMIT");

        return List.of(
                IrChunk.create(scope, 0, IrChunk.KIND_PROGRAM_NODE, program),
                IrChunk.create(scope, 1, IrChunk.KIND_ENTRY, entry),
                IrChunk.create(scope, 2, IrChunk.KIND_COVERAGE_GAP, gap));
    }

    public AnalyzerSubmission successSubmission(List<IrChunk> chunks, String submissionId) {
        IrChunkManifest manifest = IrChunkManifest.of(chunks);
        AnalyzerResourceUsage usage = new AnalyzerResourceUsage(
                chunks.size(), manifest.totalPayloadBytes(), 40, 4);
        return new AnalyzerSubmission(
                AnalyzerContracts.SCHEMA_VERSION,
                submissionId,
                scope,
                artifactDigest,
                policyDigest,
                STATIC_CAPABILITIES,
                manifest,
                List.of(AnalyzerDiagnostic.info("ANALYSIS_COMPLETE", "test-js static slice ok")),
                List.of(new AnalyzerCoverageGapDto(
                        "gap-js-dynamic-import-1",
                        CoverageGap.KIND_UNRESOLVED_CALL,
                        "dynamic import() target unresolved",
                        "STATIC_LIMIT",
                        "ev-js-gap-1")),
                usage,
                AnalyzerTerminalState.SUCCESS,
                "COMPLETED",
                null);
    }

    public AnalyzerScope scope() {
        return scope;
    }
}

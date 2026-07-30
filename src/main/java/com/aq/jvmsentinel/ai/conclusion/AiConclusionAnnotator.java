package com.aq.jvmsentinel.ai.conclusion;

import com.aq.jvmsentinel.ai.NextExperimentSteps;
import com.aq.jvmsentinel.ai.RootCauseAnalysis;
import com.aq.jvmsentinel.ai.TriageConclusion;
import com.aq.jvmsentinel.ai.context.PathRunContextBuilder;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;

/** PATH/TRIAGE 结论注解与 TRIAGE finding 挂载。 */
public final class AiConclusionAnnotator {
    private final ControlPlaneStore store;
    private final PathRunContextBuilder pathRunContext;
    private final AiAuthConclusionBuilder authConclusion;

    public AiConclusionAnnotator(
            ControlPlaneStore store,
            PathRunContextBuilder pathRunContext,
            AiAuthConclusionBuilder authConclusion) {
        this.store = java.util.Objects.requireNonNull(store, "store");
        this.pathRunContext = java.util.Objects.requireNonNull(pathRunContext, "pathRunContext");
        this.authConclusion = java.util.Objects.requireNonNull(authConclusion, "authConclusion");
    }

    public String buildConclusionJson(
            SQLiteControlPlanePersistence.AiJobData job, String summary,
            List<AuthBypassCandidate> toolBypassPoCs) {
        return authConclusion.buildAuthAwareConclusion(job, summary, toolBypassPoCs, false).conclusionJson();
    }

    public static String annotateEffectiveProbeCount(String conclusionJson, int effectiveProbeCount) {
        try {
            ObjectNode node;
            try {
                node = (ObjectNode) AiConclusionJson.JSON.readTree(conclusionJson);
            } catch (Exception ignored) {
                node = AiConclusionJson.JSON.createObjectNode();
                node.put("schemaVersion", 1);
                node.put("classification", "INFERENCE");
            }
            node.put("effectiveSandboxProbeCount", Math.max(0, effectiveProbeCount));
            return node.toString();
        } catch (Exception ignored) {
            return conclusionJson;
        }
    }

    /**
     * 将 TRIAGE rootCause 持久化到 scan finding，供 dashboard/REPORT 共享结构化来源（P0-07）。
     * 证据不足时不挂载。
     */
    public void attachTriageFindingIfPresent(
            SQLiteControlPlanePersistence.AiJobData job,
            String conclusionJson,
            String actorId,
            BiConsumer<SQLiteControlPlanePersistence.AiJobData, String> triageAttachedEvent) {
        if (job == null || job.scanId() == null || conclusionJson == null || conclusionJson.isBlank()) {
            return;
        }
        TriageConclusion.ParseResult parsed = TriageConclusion.parseAndValidate(conclusionJson);
        if (parsed.insufficientEvidence() || parsed.rootCause() == null || parsed.evidenceRefs().isEmpty()) {
            return;
        }
        Map<String, Object> rootCause = TriageConclusion.toRootCauseMap(parsed);
        if (rootCause.isEmpty()) return;
        try {
            ControlPlaneStore.ScanRecord scan = store.requireScan(job.scanId());
            String entryId = "entry-unbound";
            String entryRoute = "UNBOUND";
            String sinkId = "sink-triage";
            String sinkSymbol = "TRIAGE";
            if (!parsed.rootCause().attackPath().isEmpty()) {
                RootCauseAnalysis.AttackStep first = parsed.rootCause().attackPath().get(0);
                for (String ref : first.evidenceRefs()) {
                    if (ref != null && ref.startsWith("entry:")) {
                        String candidate = ref.substring("entry:".length());
                        for (ApiDtos.EntryDto entry : scan.dto().entries()) {
                            if (entry.id().equals(candidate)
                                    || ("entry:" + entry.id()).equals(ref)) {
                                entryId = entry.id();
                                entryRoute = entry.route() == null ? entry.id() : entry.route();
                                break;
                            }
                        }
                        break;
                    }
                }
                RootCauseAnalysis.AttackStep last = parsed.rootCause().attackPath()
                        .get(parsed.rootCause().attackPath().size() - 1);
                if (!last.label().isBlank()) {
                    sinkSymbol = last.label().length() > 128
                            ? last.label().substring(0, 128) : last.label();
                }
            }
            String cwe = parsed.rootCause().cweId().isBlank() ? "" : parsed.rootCause().cweId();
            String title = cwe.isBlank()
                    ? "TRIAGE root-cause finding"
                    : "TRIAGE " + cwe;
            String findingId = "finding-triage-" + job.aiJobId();
            String verification = TriageConclusion.CLASSIFICATION_INFERENCE;
            ApiDtos.FindingDto finding = new ApiDtos.FindingDto(
                    ApiDtos.SCHEMA_VERSION,
                    scan.dto().projectId(),
                    scan.dto().artifactDigest(),
                    scan.dto().scanId(),
                    findingId,
                    title,
                    "medium",
                    verification,
                    entryId,
                    entryRoute,
                    sinkId,
                    sinkSymbol,
                    "none",
                    List.of("none"),
                    parsed.evidenceRefs(),
                    parsed.evidenceRefs().size(),
                    0.55d,
                    ApiDtos.MOCK,
                    rootCause);
            store.attachTriageFinding(job.scanId(), finding);
            if (triageAttachedEvent != null) {
                triageAttachedEvent.accept(job,
                        "findingId=" + findingId + " evidenceRefs=" + parsed.evidenceRefs().size());
            }
        } catch (RuntimeException ignored) {
            // 挂载相对 job 完成为 best-effort；结论 JSON 仍持久化。
        }
    }

    /** PATH/TRIAGE：解析 nextExperiments，仅保留 sandbox_probe 可消费步骤。 */
    public String annotateNextExperiments(
            SQLiteControlPlanePersistence.AiJobData job, String summary, String conclusionJson) {
        Set<String> entries = Set.of();
        try {
            entries = store.requireScan(job.scanId()).dto().entries().stream()
                    .map(entry -> "entry:" + entry.id())
                    .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
        } catch (RuntimeException ignored) {
            // 空 allow-list 时仍做结构校验。
        }
        Set<String> pathRunIds = pathRunContext.loadPathRuns(job).stream()
                .map(ApiDtos.PathRunDto::pathRunId)
                .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
        NextExperimentSteps.ParseResult parsed = NextExperimentSteps.parseAndValidate(
                conclusionJson + "\n" + summary, entries, pathRunIds);
        try {
            ObjectNode node;
            try {
                node = (ObjectNode) AiConclusionJson.JSON.readTree(conclusionJson);
            } catch (Exception ignored) {
                node = AiConclusionJson.JSON.createObjectNode();
                node.put("schemaVersion", 1);
                node.put("classification", "INFERENCE");
                node.put("summary", summary == null ? "" : summary);
            }
            ArrayNode array = node.putArray("nextExperiments");
            for (var step : parsed.steps()) {
                ObjectNode row = AiConclusionJson.JSON.createObjectNode();
                row.put("entryRef", step.entryRef());
                row.put("objective", step.objective());
                row.put("track", step.track().name());
                if (!step.techniqueId().isBlank()) row.put("techniqueId", step.techniqueId());
                ArrayNode inputs = row.putArray("candidateInputs");
                step.candidateInputs().forEach(inputs::add);
                ArrayNode refs = row.putArray("pathRunRefs");
                step.pathRunRefs().forEach(refs::add);
                if (!step.rationale().isBlank()) row.put("rationale", step.rationale());
                array.add(row);
            }
            if (!parsed.rejected().isEmpty()) {
                ArrayNode rejected = node.putArray("rejectedNextExperiments");
                parsed.rejected().stream().limit(16).forEach(rejected::add);
            }
            node.put("nextExperimentsSource", "SERVER_GATED");
            return node.toString();
        } catch (Exception failure) {
            return conclusionJson;
        }
    }
}

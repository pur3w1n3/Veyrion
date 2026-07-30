package com.aq.jvmsentinel.ai.conclusion;

import com.aq.jvmsentinel.ai.AuthBypassFeasibility;
import com.aq.jvmsentinel.ai.TriageConclusion;
import com.aq.jvmsentinel.ai.context.AuthContextBuilder;
import com.aq.jvmsentinel.ai.context.PathRunContextBuilder;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.provider.AgentRole;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** AUTH/TRIAGE 结论构建、code_query 门禁与 tool bypassPoC 收集。 */
public final class AiAuthConclusionBuilder {
    private final ControlPlaneStore store;
    private final AuthContextBuilder authContext;
    private final PathRunContextBuilder pathRunContext;

    public AiAuthConclusionBuilder(
            ControlPlaneStore store,
            AuthContextBuilder authContext,
            PathRunContextBuilder pathRunContext) {
        this.store = java.util.Objects.requireNonNull(store, "store");
        this.authContext = java.util.Objects.requireNonNull(authContext, "authContext");
        this.pathRunContext = java.util.Objects.requireNonNull(pathRunContext, "pathRunContext");
    }

    public AuthConclusionBuilt buildAuthAwareConclusion(
            SQLiteControlPlanePersistence.AiJobData job, String summary,
            List<AuthBypassCandidate> toolBypassPoCs, boolean repairAlreadyAsked) {
        return buildAuthAwareConclusion(job, summary, toolBypassPoCs, repairAlreadyAsked, 0, true, true);
    }

    public AuthConclusionBuilt buildAuthAwareConclusion(
            SQLiteControlPlanePersistence.AiJobData job, String summary,
            List<AuthBypassCandidate> toolBypassPoCs, boolean repairAlreadyAsked,
            int codeQuerySuccessCount, boolean codeQueryRepairAsked, boolean diversityRepairAsked) {
        if (job.role() == AgentRole.VULNERABILITY_TRIAGE) {
            // TRIAGE 须保留 rootCause / evidenceRefs；不得走 AUTH PoC 序列化路径。
            TriageConclusion.ParseResult triage = TriageConclusion.parseAndValidate(summary);
            String conclusion = TriageConclusion.toConclusionNode(summary, triage).toString();
            return new AuthConclusionBuilt(
                    conclusion,
                    new AuthBypassFeasibility.AuthSurface(false, 0, 0, 0, 0, List.of()),
                    false, false, false, false, 0, AuthBypassFeasibility.AUTH_PASS_INITIAL);
        }
        if (job.role() != AgentRole.AUTH_ANALYSIS) {
            return new AuthConclusionBuilt(
                    AiConclusionJson.encode(Map.of(
                            "schemaVersion", 1, "classification", "INFERENCE",
                            "summary", summary, "evidenceRefs", List.of())),
                    new AuthBypassFeasibility.AuthSurface(false, 0, 0, 0, 0, List.of()),
                    false, false, false, false, 0, AuthBypassFeasibility.AUTH_PASS_INITIAL);
        }
        List<ApiDtos.PathRunDto> pathRuns = pathRunContext.loadPathRuns(job);
        String authPass = authContext.isAuthBypassConfirmPass(job, pathRuns)
                ? AuthBypassFeasibility.AUTH_PASS_CONFIRM
                : AuthBypassFeasibility.AUTH_PASS_INITIAL;
        Set<String> allowedEntries = allowedEntryRefs(job);
        Set<String> gate = allowedEntries.isEmpty() ? null : allowedEntries;
        AuthBypassFeasibility.ParseResult parsed =
                AuthBypassFeasibility.parseAndValidate(summary, gate);
        List<AuthBypassCandidate> validatedTools = new ArrayList<>();
        List<String> rejected = new ArrayList<>(parsed.rejected());
        for (AuthBypassCandidate candidate : toolBypassPoCs == null ? List.<AuthBypassCandidate>of()
                : toolBypassPoCs) {
            try {
                if (gate != null && !gate.contains(candidate.entryRef())) {
                    rejected.add("ENTRYPOINT_NOT_FOUND:" + candidate.entryRef());
                    continue;
                }
                validatedTools.add(candidate);
            } catch (RuntimeException invalid) {
                rejected.add(invalid.getMessage() == null ? "INVALID_TOOL_POC" : invalid.getMessage());
            }
        }
        List<AuthBypassCandidate> merged = AuthBypassFeasibility.merge(validatedTools, parsed);
        AuthBypassFeasibility.AuthSurface surface = authContext.loadAuthSurface(job);
        boolean needsCodeQuery = AuthBypassFeasibility.AUTH_PASS_INITIAL.equals(authPass)
                && surface.present()
                && codeQuerySuccessCount <= 0;
        if (needsCodeQuery && !codeQueryRepairAsked) {
            return new AuthConclusionBuilt("", surface, false, true, false, false, 0, authPass);
        }
        int infeasibleEvidence = AuthBypassFeasibility.countInfeasibleEvidence(summary);
        boolean sparse = AuthBypassFeasibility.AUTH_PASS_INITIAL.equals(authPass)
                && AuthBypassFeasibility.isSparseMechanisms(merged, surface, infeasibleEvidence);
        boolean incomplete = AuthBypassFeasibility.isIncomplete(merged, surface);
        if (incomplete && !repairAlreadyAsked) {
            return new AuthConclusionBuilt("", surface, true, needsCodeQuery, false, false, 0, authPass);
        }
        if (sparse && !incomplete && !diversityRepairAsked) {
            return new AuthConclusionBuilt("", surface, false, needsCodeQuery, true, false,
                    AuthBypassFeasibility.distinctMechanismCount(merged), authPass);
        }
        boolean seeded = false;
        String emptyReason = parsed.emptyReason();
        AuthBypassFeasibility.EnforcementMeta enforcement = null;
        rejected = new ArrayList<>(rejected);
        if (needsCodeQuery) {
            rejected.add(AuthBypassFeasibility.CODE_QUERY_REQUIRED);
            emptyReason = AuthBypassFeasibility.CODE_QUERY_REQUIRED
                    + ": auth surface present but code_query never succeeded";
        }
        if (incomplete || sparse) {
            ApiDtos.ScanDto scanDto = null;
            try {
                scanDto = store.requireScan(job.scanId()).dto();
            } catch (RuntimeException ignored) {
                // 无种子条目时继续降级。
            }
            java.nio.file.Path artifactPath = null;
            try {
                ControlPlaneStore.ProjectRecord project = store.requireProject(job.projectId());
                var artifact = store.artifact(project, job.artifactDigest());
                if (artifact != null) {
                    artifactPath = artifact.normalizedPath();
                }
            } catch (RuntimeException ignored) {
                artifactPath = null;
            }
            List<AuthBypassCandidate> drafts =
                    AuthBypassFeasibility.seedRuleGeneratedDrafts(scanDto, artifactPath);
            if (!drafts.isEmpty()) {
                if (incomplete) {
                    merged = drafts;
                } else {
                    Map<String, AuthBypassCandidate> combined = new LinkedHashMap<>();
                    for (AuthBypassCandidate candidate : merged) {
                        combined.put(candidate.entryRef() + "|" + candidate.techniqueId(), candidate);
                    }
                    for (AuthBypassCandidate draft : drafts) {
                        combined.putIfAbsent(draft.entryRef() + "|" + draft.techniqueId(), draft);
                        if (combined.size() >= AuthBypassFeasibility.AUTH_POC_MECHANISM_MIN) {
                            break;
                        }
                    }
                    merged = List.copyOf(combined.values());
                }
                seeded = true;
                if (!needsCodeQuery) {
                    emptyReason = incomplete
                            ? "AI omitted structured bypassPoCs on auth surface; "
                            + "RULE_GENERATED drafts seeded after " + AuthBypassFeasibility.ENFORCEMENT_REQUIRED
                            : "AI emitted sparse bypassPoCs; RULE_GENERATED fillers seeded after "
                            + AuthBypassFeasibility.POC_DIVERSITY_REQUIRED;
                }
                rejected.add(incomplete
                        ? AuthBypassFeasibility.ENFORCEMENT_REQUIRED
                        : AuthBypassFeasibility.POC_DIVERSITY_REQUIRED);
            } else if (!needsCodeQuery) {
                emptyReason = emptyReason.isBlank()
                        ? AuthBypassFeasibility.INSUFFICIENT_EVIDENCE
                        + ": auth surface present but no seedable entries"
                        : emptyReason;
            }
        }
        if (needsCodeQuery) {
            // 初始轮次无成功 code_query 时不得标记 AUTH 已满足。
            enforcement = new AuthBypassFeasibility.EnforcementMeta(
                    true, AuthBypassFeasibility.INSUFFICIENT_EVIDENCE,
                    seeded ? AuthBypassFeasibility.DRAFT_RULE_GENERATED : "", true);
        } else if (seeded) {
            enforcement = new AuthBypassFeasibility.EnforcementMeta(
                    true, AuthBypassFeasibility.ENFORCEMENT_SEEDED,
                    AuthBypassFeasibility.DRAFT_RULE_GENERATED, true);
        } else if (surface.present() && !merged.isEmpty()) {
            enforcement = new AuthBypassFeasibility.EnforcementMeta(
                    true, AuthBypassFeasibility.ENFORCEMENT_SATISFIED, "",
                    repairAlreadyAsked || codeQueryRepairAsked || diversityRepairAsked);
        } else {
            enforcement = new AuthBypassFeasibility.EnforcementMeta(
                    surface.present(), "", "", repairAlreadyAsked);
        }
        AuthBypassFeasibility.BypassConfirmation confirmation =
                AuthBypassFeasibility.evaluateBypassConfirmation(summary, pathRuns, merged);
        com.fasterxml.jackson.databind.node.ObjectNode conclusionNode = AuthBypassFeasibility.toConclusionNode(
                summary, merged, emptyReason, rejected, enforcement, confirmation);
        conclusionNode.put("authPass", authPass);
        conclusionNode.put("codeQuerySuccessCount", Math.max(0, codeQuerySuccessCount));
        conclusionNode.put("distinctMechanismCount",
                AuthBypassFeasibility.distinctMechanismCount(merged));
        return new AuthConclusionBuilt(conclusionNode.toString(), surface, false, false, false,
                seeded, merged.size(), authPass);
    }

    public boolean authCodeQueryCountsTowardGate(String scanId, ToolResult result) {
        if (!hasPersistedIrMethods(scanId)) {
            return true;
        }
        if (result == null || result.outputs() == null) {
            return false;
        }
        for (CanonicalToolContracts.ToolOutput output : result.outputs()) {
            if (output == null || output.value() == null || !output.value().has("kind")) {
                continue;
            }
            String kind = output.value().get("kind").asText("").trim().toUpperCase(Locale.ROOT);
            if ("METHOD_VIEW".equals(kind) || "GUARD_QUERY".equals(kind)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasPersistedIrMethods(String scanId) {
        if (scanId == null || scanId.isBlank()) {
            return false;
        }
        Optional<StaticFactSnapshot> facts = store.staticFacts(scanId);
        if (facts.isEmpty()) {
            return false;
        }
        return StaticFactSnapshot.hasNonEmptyMethodsIr(facts.get());
    }

    public record AuthConclusionBuilt(
            String conclusionJson,
            AuthBypassFeasibility.AuthSurface authSurface,
            boolean needsRepair,
            boolean needsCodeQuery,
            boolean needsDiversity,
            boolean seeded,
            int candidateCount,
            String authPass
    ) { }


    private Set<String> allowedEntryRefs(SQLiteControlPlanePersistence.AiJobData job) {
        if (job.scanId() == null) return Set.of();
        try {
            ControlPlaneStore.ScanRecord scan = store.requireScan(job.scanId());
            Set<String> refs = new LinkedHashSet<>();
            for (ApiDtos.EntryDto entry : scan.dto().entries()) {
                refs.add("entry:" + entry.id());
            }
            return Set.copyOf(refs);
        } catch (RuntimeException ignored) {
            return Set.of();
        }
    }

    public static void collectBypassPoCFromTool(
            List<AuthBypassCandidate> sink, ToolResult result) {
        if (result == null || result.outputs() == null) return;
        for (var output : result.outputs()) {
            if (output.value() == null) continue;
            JsonNode poc = output.value().get("bypassPoC");
            if (poc == null) poc = output.value().get("bypassCandidate");
            if (poc == null || !poc.isObject()) continue;
            try {
                com.fasterxml.jackson.databind.node.ObjectNode wrapper = AiConclusionJson.JSON.createObjectNode();
                wrapper.putArray("bypassPoCs").add(poc);
                AuthBypassFeasibility.ParseResult parsed =
                        AuthBypassFeasibility.parseAndValidate(wrapper.toString(), null);
                sink.addAll(parsed.candidates());
            } catch (RuntimeException ignored) {
                // 无效 tool PoC 丢弃；job 继续。
            }
        }
    }
}

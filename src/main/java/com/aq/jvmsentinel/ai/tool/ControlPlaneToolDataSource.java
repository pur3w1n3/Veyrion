package com.aq.jvmsentinel.ai.tool;

import com.aq.jvmsentinel.ai.tool.datasource.CodeQuerySupport;
import com.aq.jvmsentinel.ai.tool.datasource.CoverageGapSupport;
import com.aq.jvmsentinel.ai.tool.datasource.DatasourceScope;
import com.aq.jvmsentinel.ai.tool.datasource.FactsSearchSupport;
import com.aq.jvmsentinel.ai.tool.datasource.IrProjectionSupport;
import com.aq.jvmsentinel.ai.tool.datasource.PathRunFactSupport;
import com.aq.jvmsentinel.ai.tool.datasource.ScanMemorySectionLoader;
import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.experiment.ExperimentPlanKind;
import com.aq.jvmsentinel.domain.experiment.HypothesisExperimentPlan;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.worker.HypothesisExperimentPlanValidator;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * 已持久化 scan 的只读投影。默认路径从不执行制品；
 * {@link #queryCode} 可对已注册制品做有界 ZIP 字符串/配置扫描
 * （与 synthetic identity harvest 相同信任边界）。
 */
public final class ControlPlaneToolDataSource implements ToolDataSource {
    private final ControlPlaneStore store;
    private final String scanId;
    private final DatasourceScope datasourceScope;
    private final ScanMemorySectionLoader scanMemoryLoader;
    private final CodeQuerySupport codeQuery;
    private final FactsSearchSupport factsSearch;
    private final CoverageGapSupport coverageGapSupport;
    private final DynamicProbeExecutor dynamicProbeExecutor;
    private final ExperimentPlanAcceptor experimentPlanAcceptor;

    public ControlPlaneToolDataSource(ControlPlaneStore store, String scanId) {
        this(store, scanId, (projectId, artifactDigest, scopedScanId) -> List.of());
    }

    public ControlPlaneToolDataSource(ControlPlaneStore store, String scanId,
                                      DynamicEvidenceSource dynamicEvidenceSource) {
        this(store, scanId, dynamicEvidenceSource, (scopedScanId, scope, principalId, jobId, toolCallId,
                entrypointRef, candidateInputs, maxRequests, techniqueId, authorizationHeader, bladeAuthHeader,
                experimentPlanId) -> Optional.empty());
    }

    public ControlPlaneToolDataSource(ControlPlaneStore store, String scanId,
                                      DynamicEvidenceSource dynamicEvidenceSource,
                                      DynamicProbeExecutor dynamicProbeExecutor) {
        this(store, scanId, dynamicEvidenceSource, dynamicProbeExecutor,
                (projectId, artifactDigest, scopedScanId) -> List.of());
    }

    public ControlPlaneToolDataSource(ControlPlaneStore store, String scanId,
                                      DynamicEvidenceSource dynamicEvidenceSource,
                                      DynamicProbeExecutor dynamicProbeExecutor,
                                      PathRunSource pathRunSource) {
        this(store, scanId, dynamicEvidenceSource, dynamicProbeExecutor, pathRunSource,
                (scopedScanId, plan) -> { });
    }

    public ControlPlaneToolDataSource(ControlPlaneStore store, String scanId,
                                      DynamicEvidenceSource dynamicEvidenceSource,
                                      DynamicProbeExecutor dynamicProbeExecutor,
                                      PathRunSource pathRunSource,
                                      ExperimentPlanAcceptor experimentPlanAcceptor) {
        this.store = Objects.requireNonNull(store, "store");
        this.scanId = Objects.requireNonNull(scanId, "scanId");
        this.datasourceScope = new DatasourceScope(store, scanId, pathRunSource, dynamicEvidenceSource);
        this.scanMemoryLoader = new ScanMemorySectionLoader(store, scanId, pathRunSource);
        IrProjectionSupport irProjection = new IrProjectionSupport(store, scanId);
        this.codeQuery = new CodeQuerySupport(store, scanId, irProjection);
        this.factsSearch = new FactsSearchSupport(datasourceScope, store, scanId);
        this.coverageGapSupport = new CoverageGapSupport(store);
        this.dynamicProbeExecutor = Objects.requireNonNull(dynamicProbeExecutor, "dynamicProbeExecutor");
        this.experimentPlanAcceptor = Objects.requireNonNull(experimentPlanAcceptor, "experimentPlanAcceptor");
    }

    @Override
    public Optional<FactRecord> getScanMemory(ToolExecutionContext.Scope scope, String section, String role) {
        return scanMemoryLoader.load(scope, section, role, datasourceScope);
    }

    @Override
    public List<FactRecord> queryCode(ToolExecutionContext.Scope scope, String query, int limit) {
        return queryCode(scope, "", query, limit);
    }

    @Override
    public List<FactRecord> queryCode(ToolExecutionContext.Scope scope, String kind,
                                      String query, int limit) {
        datasourceScope.scopedScan(scope);
        return codeQuery.queryCode(scope, kind, query, limit);
    }

    @Override
    public List<FactRecord> searchFacts(ToolExecutionContext.Scope scope, String kind,
                                        String query, int limit) {
        return factsSearch.searchFacts(scope, kind, query, limit);
    }

    @Override
    public FactSearchPage searchFactsPage(ToolExecutionContext.Scope scope, String kind,
                                          String query, int limit, int offset) {
        return factsSearch.searchFactsPage(scope, kind, query, limit, offset);
    }

    @Override
    public Optional<FactRecord> findEvidence(ToolExecutionContext.Scope scope, String evidenceRef) {
        return factsSearch.findEvidence(scope, evidenceRef);
    }

    @Override
    public Optional<FactRecord> resolveEntrypoint(ToolExecutionContext.Scope scope, String entrypointRef) {
        ControlPlaneStore.ScanRecord scan = datasourceScope.scopedScan(scope);
        EntryRefResolver.Resolution resolution = EntryRefResolver.resolve(scan.dto().entries(), entrypointRef);
        if (!resolution.resolved()) {
            if (resolution.status() == EntryRefResolver.Status.AMBIGUOUS) {
                throw new IllegalArgumentException(EntryRefResolver.CODE_AMBIGUOUS);
            }
            if (resolution.status() == EntryRefResolver.Status.MUST_BE_ENTRY) {
                throw new IllegalArgumentException(EntryRefResolver.CODE_MUST_BE_ENTRY);
            }
            return Optional.empty();
        }
        return Optional.of(new FactRecord(scope, resolution.canonicalRef(),
                com.aq.jvmsentinel.ai.tool.datasource.DatasourceJson.JSON.valueToTree(resolution.entry())));
    }

    @Override
    public Optional<FactRecord> requestSandboxProbe(ToolExecutionContext.Scope scope,
                                                    String principalId, String jobId,
                                                    String toolCallId,
                                                    String entrypointRef,
                                                    List<String> candidateInputs,
                                                    int maxRequests,
                                                    String techniqueId,
                                                    String authorizationHeader,
                                                    String bladeAuthHeader,
                                                    String experimentPlanId) throws Exception {
        ControlPlaneStore.ScanRecord scan = datasourceScope.scopedScan(scope);
        ApiDtos.EntryDto entry = requireProbeEntry(scan, entrypointRef);
        if (!"HTTP".equalsIgnoreCase(entry.protocol()) || entry.route() == null || entry.method() == null) {
            throw new IllegalArgumentException("sandbox probe entry is not an eligible HTTP endpoint");
        }
        String canonical = EntryRefResolver.canonicalRef(entry);
        return dynamicProbeExecutor.request(scanId, scope, principalId, jobId, toolCallId, canonical,
                candidateInputs == null ? List.of() : List.copyOf(candidateInputs), maxRequests,
                techniqueId, authorizationHeader, bladeAuthHeader, experimentPlanId);
    }

    @Override
    public List<String> coverageGapIds(ToolExecutionContext.Scope scope) {
        ControlPlaneStore.ScanRecord scan = datasourceScope.scopedScan(scope);
        List<ApiDtos.PathRunDto> pathRuns;
        try {
            pathRuns = datasourceScope.pathRuns(scan);
        } catch (RuntimeException ignored) {
            pathRuns = List.of();
        }
        List<BytecodeFactIndex.TaintPath> taintPaths = StaticFactSnapshot.resolveTaintPaths(
                store.staticFacts(scanId), scan.dto().sinks());
        ContrastLedger.Ledger ledger = ContrastLedger.build(
                scan.dto().entries(),
                scan.dto().sinks(),
                scan.evidence(),
                pathRuns,
                taintPaths);
        List<com.aq.jvmsentinel.analysis.CoverageGapProjector.CoverageGap> gaps =
                com.aq.jvmsentinel.analysis.CoverageGapProjector.project(
                        taintPaths, ledger.rows(), scan.dto().entries());
        Set<String> preferredEntries = new LinkedHashSet<>(
                coverageGapSupport.tracePlanMissingEffectEntries(scan, taintPaths));
        Set<String> preferredTaintIds = new LinkedHashSet<>();
        for (BytecodeFactIndex.TaintPath path : taintPaths) {
            if (path == null) {
                continue;
            }
            ApiDtos.EntryDto bound = StaticFactSnapshot.findEntryForTaintSource(
                    scan.dto().entries(), scan.evidence(), path);
            if (bound != null && preferredEntries.contains(bound.id())) {
                preferredTaintIds.add(path.id());
            }
        }
        LinkedHashSet<String> ordered = new LinkedHashSet<>();
        // TracePlan gap entry 优先，便于 sandbox_probe coverageGapRef 指向它们。
        for (String entryId : preferredEntries) {
            ordered.add("traceplan-gap:" + entryId);
        }
        for (String taintId : preferredTaintIds) {
            ordered.add(taintId);
        }
        for (var gap : gaps) {
            if (gap.taintPathId() != null && !gap.taintPathId().isBlank()) {
                ordered.add(gap.taintPathId());
            }
        }
        return List.copyOf(ordered);
    }

    @Override
    public void validateHypothesisBinding(ToolExecutionContext.Scope scope,
                                           String hypothesisId,
                                           String planKind,
                                           String experimentPlanId,
                                           String entrypointRef) {
        ControlPlaneStore.ScanRecord scan = datasourceScope.scopedScan(scope);
        String requestedHypothesis = hypothesisId == null ? "" : hypothesisId.trim();
        String requestedPlan = experimentPlanId == null ? "" : experimentPlanId.trim();
        String requestedKind = planKind == null ? "" : planKind.trim();
        if (requestedHypothesis.isBlank() && requestedPlan.isBlank()) {
            return;
        }
        if (requestedHypothesis.isBlank() || requestedKind.isBlank()) {
            throw new SecurityException("HYPOTHESIS_BINDING_INCOMPLETE");
        }
        var hypothesis = store.hypothesis(requestedHypothesis);
        if (hypothesis == null || !scan.dto().scanId().equals(hypothesis.scanId())) {
            throw new SecurityException("HYPOTHESIS_SCOPE_MISMATCH");
        }
        ExperimentPlanKind kind = HypothesisExperimentPlanValidator.requirePlanKind(requestedKind);
        if (!requestedPlan.isBlank()) {
            HypothesisExperimentPlan plan = store.hypothesisExperimentPlan(requestedPlan);
            if (plan == null || !scan.dto().scanId().equals(plan.scanId())
                    || !requestedHypothesis.equals(plan.hypothesisId())
                    || plan.planKind() != kind) {
                throw new SecurityException("EXPERIMENT_PLAN_SCOPE_MISMATCH");
            }
            if (!plan.entrypointRef().isBlank()) {
                EntryRefResolver.Resolution planned = EntryRefResolver.resolve(scan.dto().entries(), plan.entrypointRef());
                EntryRefResolver.Resolution requested = EntryRefResolver.resolve(scan.dto().entries(), entrypointRef);
                if (!planned.resolved() || !requested.resolved()
                        || !planned.canonicalRef().equals(requested.canonicalRef())) {
                    throw new SecurityException("EXPERIMENT_PLAN_ENTRYPOINT_MISMATCH");
                }
            }
        }
    }

    @Override
    public void acceptExperimentPlan(ToolExecutionContext.Scope scope, ExperimentPlan plan) {
        datasourceScope.scopedScan(scope);
        experimentPlanAcceptor.accept(scanId, plan);
    }

    /** AUTH 门禁：持久化 facts 是否暴露非空 methods IR 列表。 */
    public static boolean hasNonEmptyMethodsIr(StaticFactSnapshot snapshot) {
        return IrProjectionSupport.hasNonEmptyMethodsIr(snapshot);
    }

    /** 注入 AI prompt 时使用的紧凑 PathRun HTTP/SQL 摘要。 */
    public static Map<String, Object> pathRunPromptSummary(ApiDtos.PathRunDto value) {
        return PathRunFactSupport.pathRunPromptSummary(value);
    }

    private static ApiDtos.EntryDto requireProbeEntry(ControlPlaneStore.ScanRecord scan, String entrypointRef) {
        EntryRefResolver.Resolution resolution = EntryRefResolver.resolve(scan.dto().entries(), entrypointRef);
        if (resolution.resolved()) {
            return resolution.entry();
        }
        throw new IllegalArgumentException(resolution.code());
    }

    @FunctionalInterface
    public interface DynamicEvidenceSource {
        List<ApiDtos.EvidenceDto> evidenceForScan(
                String projectId, String artifactDigest, String scanId);
    }

    @FunctionalInterface
    public interface DynamicProbeExecutor {
        Optional<FactRecord> request(String scanId, ToolExecutionContext.Scope scope, String principalId,
                                     String jobId, String toolCallId,
                                     String entrypointRef, List<String> candidateInputs, int maxRequests,
                                     String techniqueId, String authorizationHeader, String bladeAuthHeader,
                                     String experimentPlanId)
                throws Exception;
    }

    @FunctionalInterface
    public interface PathRunSource {
        List<ApiDtos.PathRunDto> pathRunsForScan(
                String projectId, String artifactDigest, String scanId);
    }

    @FunctionalInterface
    public interface ExperimentPlanAcceptor {
        void accept(String scanId, ExperimentPlan plan);
    }
}

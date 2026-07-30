package com.aq.jvmsentinel.control.http;

import com.aq.jvmsentinel.analysis.ArtifactMetadataReader;
import com.aq.jvmsentinel.analysis.PreAnalysisInput;
import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.analysis.detector.DetectorContext;
import com.aq.jvmsentinel.analysis.detector.DetectorRegistry;
import com.aq.jvmsentinel.analysis.hypothesis.SecurityHypothesisProjector;
import com.aq.jvmsentinel.analysis.ir.EvidenceGraphProjector;
import com.aq.jvmsentinel.analysis.spi.ProviderBundle;
import com.aq.jvmsentinel.analysis.spi.ProviderContext;
import com.aq.jvmsentinel.analysis.spi.ProviderContribution;
import com.aq.jvmsentinel.analysis.spi.ProviderRegistry;
import com.aq.jvmsentinel.analysis.universe.ArtifactUniverseBuilder;
import com.aq.jvmsentinel.artifact.ArtifactValidationException;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.http.ControlPlaneHttpLimits;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.control.http.ControlPlaneHandlerRecords;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.EvidenceGraph;
import com.aq.jvmsentinel.domain.ir.EvidenceGraphMerge;
import com.aq.jvmsentinel.domain.ir.IrNode;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;
import com.aq.jvmsentinel.event.EventContext;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.DependencyAccess;
import com.aq.jvmsentinel.model.Entrypoint;
import com.aq.jvmsentinel.model.Evidence;
import com.aq.jvmsentinel.model.PermissionRequirement;
import com.aq.jvmsentinel.model.Sink;
import com.aq.jvmsentinel.model.VerificationStatus;
import com.aq.jvmsentinel.policy.DangerousActionMode;
import com.aq.jvmsentinel.policy.NetworkMode;
import com.aq.jvmsentinel.policy.PolicyValidator;
import com.aq.jvmsentinel.policy.ScanPolicy;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** 从 ControlPlaneRouteHandlers 拆出的 HTTP 处理器：ScanBuild 域。 */
final class ScanBuildHttpHandlers extends ControlPlaneHandlerSupport {

    ScanBuildHttpHandlers(ControlPlaneHandlerHost host) {
        super(host);
    }

    ControlPlaneHandlerRecords.ScanStart createOrReplayScan(String projectId, Map<String, Object> body,
                                         String idempotencyHeader, String operatorId) throws IOException {
        ControlPlaneStore.ProjectRecord project = host.store.requireProject(projectId);
        ControlPlaneHttpSupport.ensureIdempotencyCapacity(host.idempotentScans,
                idempotencyHeader == null ? null : projectId + ":" + idempotencyHeader);
        String payload = JsonCodec.stringify(body);
        String durableScope = "scan:create:" + projectId;
        ControlPlaneHttpSupport.ensureIdempotencyCapacity(host.durableIdempotency,
                idempotencyHeader == null ? null : ControlPlaneHttpSupport.idempotencyMapKey(durableScope, idempotencyHeader));
        // 在服务幂等
        // replay 前解析并校验同意标志。复用 key 不得将省略的 authorization 字段
        // 变为分析 artifact 的隐式许可。
        if (!ControlPlaneHttpSupport.optionalBoolean(body, "authorized", false)) {
            throw new ControlPlaneHttpSupport.ApiException(403, "AUTHORIZATION_REQUIRED", "scan authorization is required");
        }
        SQLiteControlPlanePersistence.IdempotencyData durable = existingDurableIdempotency(
                durableScope, idempotencyHeader, payload);
        if (idempotencyHeader != null) {
            String existingId = host.idempotentScans.get(projectId + ":" + idempotencyHeader);
            if (existingId == null && durable != null) existingId = durable.resultRef();
            if (existingId != null) {
                ControlPlaneStore.ScanRecord existing = host.store.scan(existingId);
                if (existing != null) {
                    return new ControlPlaneHandlerRecords.ScanStart(existing, true);
                }
            }
        }
        String digestOrId = ControlPlaneHttpSupport.optionalText(body, "artifactDigest",
                ControlPlaneHttpSupport.optionalText(body, "artifactId", ControlPlaneHttpSupport.optionalText(body, "artifact", null)));
        if (digestOrId == null) throw new ControlPlaneHttpSupport.ApiException(400, "ARTIFACT_REQUIRED", "artifactDigest is required");
        ArtifactDescriptor descriptor = host.store.artifact(project, digestOrId);
        if (descriptor == null) throw new ControlPlaneHttpSupport.ApiException(404, "ARTIFACT_NOT_FOUND", "artifact is not registered for this project");
        ScanPolicy policy = policyFrom(body);
        PolicyValidator.requireStartAllowed(policy);
        host.artifactRegistry.verifyUnchanged(descriptor);

        String scanId = "scan-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        EventContext context = new EventContext(projectId, descriptor.sha256(), scanId, "task-preanalysis");
        publishEvent(scanId, context, "ScanCreated", "created", Map.of(
                "status", "QUEUED", "verificationStatus", ApiDtos.STATIC_INFERRED,
                "dependencyMode", ApiDtos.MOCK));
        publishEvent(scanId, context, "TaskLeased", "preanalysis", Map.of("status", "RUNNING"));

        ControlPlaneHandlerRecords.ScanBuild build;
        try {
            // 元数据提取前后均复检。此
            // 关闭文件可在读取 ZIP/class 列表时被替换的 TOCTOU 窗口。
            // （见上句）
            PreAnalysisInput analysisInput = ArtifactMetadataReader.read(descriptor);
            PreAnalysisResult result = host.analysis.analyze(analysisInput);
            host.artifactRegistry.verifyUnchanged(descriptor);
            build = buildScan(projectId, descriptor, scanId, result, analysisInput.configurationLines());
        } catch (ArtifactValidationException invalidArtifact) {
            publishEvent(scanId, context, "TaskStopped", "preanalysis", Map.of(
                    "status", "STOPPED", "reason", "INVALID_ARTIFACT"));
            throw invalidArtifact;
        } catch (IOException analysisFailure) {
            publishEvent(scanId, context, "TaskStopped", "preanalysis", Map.of(
                    "status", "STOPPED", "reason", "STATIC_ANALYSIS_FAILED"));
            throw new ControlPlaneHttpSupport.ApiException(422, "ANALYSIS_FAILED", "static metadata analysis could not complete");
        } catch (RuntimeException analysisFailure) {
            publishEvent(scanId, context, "TaskStopped", "preanalysis", Map.of(
                    "status", "STOPPED", "reason", "STATIC_ANALYSIS_FAILED"));
            throw new ControlPlaneHttpSupport.ApiException(422, "ANALYSIS_FAILED", "static metadata analysis could not complete");
        }
        ControlPlaneStore.ScanRecord scanRecord =
                new ControlPlaneStore.ScanRecord(build.scan(), build.evidence(), build.findings(), build.chains());
        host.store.saveScan(scanRecord, operatorId);
        if (build.hypotheses() != null && !build.hypotheses().isEmpty()) {
            host.store.saveHypotheses(scanId, build.hypotheses(), operatorId);
        }
        if (build.staticFacts() != null) {
            host.store.saveStaticFacts(scanId, build.staticFacts(), operatorId);
        }
        if (idempotencyHeader != null) {
            host.idempotentScans.putIfAbsent(projectId + ":" + idempotencyHeader, scanId);
            rememberDurableIdempotency(durableScope, idempotencyHeader, payload, scanId, null);
        }
        for (ApiDtos.FindingDto finding : build.findings()) {
            publishEvent(scanId, context, "FindingUpdated", finding.findingId(), Map.of(
                    "findingId", finding.findingId(), "verificationStatus", finding.verificationStatus(),
                    "evidenceRefs", finding.evidenceRefs()));
        }
        publishEvent(scanId, context, "ScanCompleted", "completed", Map.of(
                "status", "COMPLETED", "verificationStatus", ApiDtos.STATIC_INFERRED,
                "dependencyMode", ApiDtos.MOCK, "evidenceRefs", build.scan().evidenceRefs()));
        return new ControlPlaneHandlerRecords.ScanStart(scanRecord, false);
    }
    ScanPolicy policyFrom(Map<String, Object> body) {
        // mutation token 认证调用方；不等同于
        // 分析所供 artifact 的授权。要求显式
        // per-scan 同意标志，以便意外省略字段时 fail-closed。
        boolean authorized = ControlPlaneHttpSupport.optionalBoolean(body, "authorized", false);
        String network = ControlPlaneHttpSupport.optionalText(body, "networkMode", "DENY").toUpperCase(Locale.ROOT);
        String dangerous = ControlPlaneHttpSupport.optionalText(body, "dangerousActionMode", "DRY_RUN").toUpperCase(Locale.ROOT);
        NetworkMode networkMode;
        DangerousActionMode dangerousMode;
        try {
            networkMode = NetworkMode.valueOf(network);
            dangerousMode = DangerousActionMode.valueOf(dangerous);
        } catch (IllegalArgumentException invalid) {
            throw new ControlPlaneHttpSupport.ApiException(400, "INVALID_POLICY", "unsupported scan policy value");
        }
        List<String> allowlist = ControlPlaneHttpSupport.stringList(body.get("networkAllowlist"), "networkAllowlist");
        long wall = ControlPlaneHttpSupport.positiveLong(body, "maxWallClockSeconds", ControlPlaneHttpLimits.DEFAULT_WALL_CLOCK_SECONDS);
        long memory = ControlPlaneHttpSupport.positiveLong(body, "maxMemoryBytes", ControlPlaneHttpLimits.DEFAULT_MEMORY_BYTES);
        long disk = ControlPlaneHttpSupport.positiveLong(body, "maxDiskBytes", ControlPlaneHttpLimits.DEFAULT_DISK_BYTES);
        return new ScanPolicy(authorized, networkMode, dangerousMode, allowlist, wall, memory, disk);
    }
    ControlPlaneHandlerRecords.ScanBuild buildScan(String projectId, ArtifactDescriptor descriptor, String scanId,
                                PreAnalysisResult result, List<String> configurationLines) {
        String now = Instant.now(host.clock).toString();
        Map<String, String> evidenceIds = new LinkedHashMap<>();
        Map<String, ApiDtos.EvidenceDto> evidence = new LinkedHashMap<>();
        for (Evidence source : result.entryCatalog().evidence()) {
            String id = "evidence-" + scanId + "-" + source.evidenceId();
            evidenceIds.put(source.evidenceId(), id);
            evidence.put(id, new ApiDtos.EvidenceDto(ApiDtos.SCHEMA_VERSION, projectId,
                    descriptor.sha256(), scanId, id, source.kind().name(), source.source(),
                    source.confidence(), source.summary(), now, "jvm-sentinel-preanalysis/0.1",
                    "none", "artifact:" + descriptor.sha256(), ApiDtos.MOCK));
        }
        List<ApiDtos.EntryDto> entries = new ArrayList<>();
        Map<String, List<String>> entryRefs = new LinkedHashMap<>();
        Map<String, List<String>> permissionPreconditions = new LinkedHashMap<>();
        for (PermissionRequirement permission : result.permissionMatrix().requirements()) {
            List<String> conditions = new ArrayList<>();
            for (String role : permission.roles()) conditions.add("ROLE=" + role);
            for (String tenant : permission.tenants()) conditions.add("TENANT=" + tenant);
            for (String state : permission.states()) conditions.add("STATE=" + state);
            permissionPreconditions.put(permission.entrypointId(), List.copyOf(conditions));
        }
        for (Entrypoint source : result.entryCatalog().entries()) {
            List<String> refs = prefixRefs(source.evidenceRefs(), evidenceIds);
            String module = simpleName(source.declaringClass());
            int coverage = source.status() == VerificationStatus.STATIC_INFERRED ? 0 : 0;
            List<String> preconditions = new ArrayList<>(source.preconditions());
            preconditions.addAll(permissionPreconditions.getOrDefault(source.id(), List.of()));
            entries.add(new ApiDtos.EntryDto(ApiDtos.SCHEMA_VERSION, projectId, descriptor.sha256(), scanId,
                    source.id(), source.protocol(), source.method(), source.route(), source.declaringClass(), module,
                    source.parameters(), preconditions, source.status().name(), source.confidence(), coverage, refs));
            entryRefs.put(source.id(), refs);
        }
        List<ApiDtos.DependencyDto> dependencies = new ArrayList<>();
        for (DependencyAccess source : result.dependencyMap().accesses()) {
            dependencies.add(new ApiDtos.DependencyDto(ApiDtos.SCHEMA_VERSION, projectId, descriptor.sha256(), scanId,
                    source.id(), source.kind(), source.target(), source.accessType(), source.mode(), source.fields(),
                    source.status().name(), source.confidence(), prefixRefs(source.evidenceRefs(), evidenceIds)));
        }
        List<ApiDtos.SinkDto> sinks = new ArrayList<>();
        for (Sink source : result.sinkCatalog().sinks()) {
            sinks.add(new ApiDtos.SinkDto(ApiDtos.SCHEMA_VERSION, projectId, descriptor.sha256(), scanId,
                    source.id(), source.category(), source.symbol(), source.source(), source.status().name(),
                    source.confidence(), prefixRefs(source.evidenceRefs(), evidenceIds)));
        }
        // P1-03：ProviderBundle/Registry 为 entry/effect/guard 权威来源（薄合并）。
        ProviderRegistry.ensureDefaults();
        ProviderContext providerContext = ProviderContext.of(
                projectId, descriptor.sha256(), scanId, descriptor, result);
        ProviderBundle providerBundle = ProviderRegistry.collect(providerContext);
        mergeProviderBundleIntoScan(
                providerBundle, projectId, descriptor.sha256(), scanId, now, entries, sinks, evidence);
        BytecodeFactIndex factIndex = result.bytecodeFactIndex();
        List<String> entryProtocols = new ArrayList<>();
        for (Entrypoint source : result.entryCatalog().entries()) {
            entryProtocols.add(source.protocol());
        }
        ArtifactUniverse artifactUniverse =
                ArtifactUniverseBuilder.build(descriptor, factIndex, entryProtocols);
        StaticFactSnapshot staticFacts =
                StaticFactSnapshot.fromBytecodeIndex(factIndex, artifactUniverse);
        SecurityHypothesisProjector.Result projected = buildFindings(
                projectId, descriptor, scanId, entries, dependencies, sinks, evidence, factIndex.taintPaths());
        DetectorContext detectorContext = new DetectorContext(
                scanId,
                artifactUniverse,
                staticFacts,
                entries,
                sinks,
                dependencies,
                evidence,
                configurationLines,
                descriptor.normalizedPath());
        List<SecurityHypothesis> detected = new ArrayList<>(
                DetectorRegistry.defaults().analyzeAll(detectorContext));
        for (ProviderContribution.Detector detector : providerBundle.detectors()) {
            if (detector != null && detector.hypothesis() != null) {
                detected.add(detector.hypothesis());
            }
        }
        List<SecurityHypothesis> hypotheses =
                SecurityHypothesisProjector.mergeWithDetectors(projected.hypotheses(), detected);
        // 高信号非污点 detector 假设（如 rememberMe 加密）→ findings STATIC_INFERRED。
        List<ApiDtos.FindingDto> findings = SecurityHypothesisProjector.mergeFindingsWithDetectorHypotheses(
                projectId, descriptor.sha256(), scanId, projected.findings(), hypotheses, dependencies);
        List<ApiDtos.PathDto> paths = buildPaths(
                projectId, descriptor, scanId, entries, sinks, evidence);
        List<String> allEvidence = new ArrayList<>(evidence.keySet());
        List<ApiDtos.AttackChainDto> chains = buildChains(
                projectId, descriptor.sha256(), scanId, findings);
        ApiDtos.ScanDto scan = new ApiDtos.ScanDto(ApiDtos.SCHEMA_VERSION, projectId, descriptor.sha256(), scanId,
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now, allEvidence,
                entries, dependencies, sinks, findings, paths);
        // P1-02：在 StaticFactSnapshot 内持久化权威 Evidence Graph 线格式（schema v4）。
        EvidenceGraph authoritativeGraph = EvidenceGraphProjector.fromScan(
                scanId,
                Optional.of(staticFacts),
                entries,
                sinks,
                dependencies,
                hypotheses,
                findings,
                List.of());
        List<IrNode> providerNodes = new ArrayList<>();
        for (ProviderContribution.TrustBoundary contribution : providerBundle.trustBoundaries()) {
            if (contribution != null && contribution.node() != null) providerNodes.add(contribution.node());
        }
        for (ProviderContribution.Guard contribution : providerBundle.guards()) {
            if (contribution != null && contribution.node() != null) providerNodes.add(contribution.node());
        }
        for (ProviderContribution.Sanitizer contribution : providerBundle.sanitizers()) {
            if (contribution != null && contribution.node() != null) providerNodes.add(contribution.node());
        }
        authoritativeGraph = EvidenceGraphMerge.withExtraNodes(authoritativeGraph, providerNodes);
        staticFacts = staticFacts.withEvidenceGraph(authoritativeGraph);
        return new ControlPlaneHandlerRecords.ScanBuild(scan, evidence, findings, chains, staticFacts, hypotheses);
    }

    /**
     * P1-01: 将运行时加载类列表合并进持久化 universe 与 CoverageMatrix 缺口。
     * agent/fixture 回调使用；纯静态 scan 保持空列表。
     */
    SecurityHypothesisProjector.Result buildFindings(String projectId, ArtifactDescriptor descriptor,
                                                             String scanId,
                                                             List<ApiDtos.EntryDto> entries,
                                                             List<ApiDtos.DependencyDto> dependencies,
                                                             List<ApiDtos.SinkDto> sinks,
                                                             Map<String, ApiDtos.EvidenceDto> evidence,
                                                             List<BytecodeFactIndex.TaintPath> taintPaths) {
        return SecurityHypothesisProjector.project(
                projectId,
                descriptor.sha256(),
                scanId,
                entries,
                dependencies,
                sinks,
                evidence,
                taintPaths,
                ControlPlaneHandlerSupport::sinkBindingKey,
                ControlPlaneHandlerSupport::entryBindingKey,
                (category, confidence, bound) -> bound
                        ? staticSinkSeverity(category, confidence)
                        : "info",
                ControlPlaneHandlerSupport::sinkCategoryLabel);
    }
    List<ApiDtos.PathDto> buildPaths(String projectId, ArtifactDescriptor descriptor, String scanId,
                                              List<ApiDtos.EntryDto> entries,
                                              List<ApiDtos.SinkDto> sinks,
                                              Map<String, ApiDtos.EvidenceDto> evidence) {
        List<ApiDtos.PathDto> paths = new ArrayList<>();
        for (ApiDtos.EntryDto entry : entries) {
            List<ApiDtos.PathStepDto> steps = new ArrayList<>();
            LinkedHashSet<String> pathEvidence = new LinkedHashSet<>(entry.evidenceRefs());
            steps.add(new ApiDtos.PathStepDto(entry.method() + " " + entry.route(),
                    "入口类=" + entry.declaringClass() + " · 静态元数据", "entry", "done", entry.evidenceRefs()));
            for (ApiDtos.SinkDto sink : sinks) {
                if (!entryBindingKey(entry, evidence).equals(sinkBindingKey(sink, evidence))) continue;
                steps.add(new ApiDtos.PathStepDto(sink.symbol(), "类别=" + sinkCategoryLabel(sink.category())
                        + " · 同一处理函数内的字节码调用候选；污点与运行时执行尚未证明",
                        "sink", "blocked", sink.evidenceRefs()));
                pathEvidence.addAll(sink.evidenceRefs());
            }
            paths.add(new ApiDtos.PathDto(ApiDtos.SCHEMA_VERSION, projectId, descriptor.sha256(), scanId,
                    "path-" + scanId + "-" + entry.id(), entry.id(), ApiDtos.STATIC_INFERRED, ApiDtos.MOCK,
                    entry.preconditions(), "STATIC_ONLY_NOT_EXECUTED", List.copyOf(pathEvidence), steps));
        }
        return paths;
    }
    List<ApiDtos.AttackChainDto> buildChains(String projectId, String artifactDigest, String scanId,
                                                      List<ApiDtos.FindingDto> findings) {
        Map<String, List<ApiDtos.FindingDto>> byEntry = new LinkedHashMap<>();
        for (ApiDtos.FindingDto finding : findings) {
            if (!"entry-unbound".equals(finding.entrypointId())) {
                byEntry.computeIfAbsent(finding.entrypointId(), ignored -> new ArrayList<>()).add(finding);
            }
        }
        List<ApiDtos.AttackChainDto> result = new ArrayList<>();
        int index = 0;
        for (Map.Entry<String, List<ApiDtos.FindingDto>> group : byEntry.entrySet()) {
            if (group.getValue().size() < 2) continue;
            List<String> findingRefs = group.getValue().stream().map(ApiDtos.FindingDto::findingId).toList();
            LinkedHashSet<String> groupEvidence = new LinkedHashSet<>();
            for (ApiDtos.FindingDto finding : group.getValue()) groupEvidence.addAll(finding.evidenceRefs());
            double confidence = group.getValue().stream()
                    .mapToDouble(ApiDtos.FindingDto::confidence).min().orElse(0);
            result.add(new ApiDtos.AttackChainDto(ApiDtos.SCHEMA_VERSION, projectId, artifactDigest, scanId,
                    "chain-" + scanId + "-" + (++index),
                    "同一静态入口处理类上的多个敏感调用候选（数据流尚未验证）",
                    confidence, ApiDtos.STATIC_INFERRED, findingRefs, List.copyOf(groupEvidence)));
        }
        return List.copyOf(result);
    }
}

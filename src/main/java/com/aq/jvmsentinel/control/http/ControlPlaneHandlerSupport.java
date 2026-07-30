package com.aq.jvmsentinel.control.http;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.analysis.experiment.PathDebugWireHelper;
import com.aq.jvmsentinel.analysis.hypothesis.SecurityHypothesisProjector;
import com.aq.jvmsentinel.analysis.spi.ProviderContribution;
import com.aq.jvmsentinel.analysis.spi.ProviderBundle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.EffectNode;
import com.aq.jvmsentinel.domain.ir.EntryNode;
import com.aq.jvmsentinel.domain.ir.GuardNode;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.aq.jvmsentinel.worker.WorkerTaskSpec;
import com.aq.jvmsentinel.provider.ProviderContracts.ModelInventory;
import com.aq.jvmsentinel.artifact.ArtifactUploadService;
import com.aq.jvmsentinel.event.EventContext;
import com.aq.jvmsentinel.event.EventFactory;
import com.aq.jvmsentinel.event.IdempotencyKey;
import com.aq.jvmsentinel.event.VersionedEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** 处理器共享辅助（wire 映射、幂等、投影工具）。 */
class ControlPlaneHandlerSupport {
    protected final ControlPlaneHandlerHost host;

    ControlPlaneHandlerSupport(ControlPlaneHandlerHost host) {
        this.host = host;
    }

    SQLiteControlPlanePersistence.IdempotencyData existingDurableIdempotency(
            String scope, String key, String payload) {
        if (key == null) return null;
        SQLiteControlPlanePersistence.IdempotencyData record = host.durableIdempotency.get(ControlPlaneHttpSupport.idempotencyMapKey(scope, key));
        if (record == null) return null;
        if (!record.payloadHash().equals(ControlPlaneHttpSupport.payloadHash(payload))) {
            throw new ControlPlaneHttpSupport.ApiException(409, "IDEMPOTENCY_CONFLICT",
                    "Idempotency-Key was already used with a different request");
        }
        return record;
    }
    SQLiteControlPlanePersistence.IdempotencyData rememberDurableIdempotency(
            String scope, String key, String payload, String resultRef, String resultJson) {
        if (key == null) return null;
        String mapKey = ControlPlaneHttpSupport.idempotencyMapKey(scope, key);
        ControlPlaneHttpSupport.ensureIdempotencyCapacity(host.durableIdempotency, mapKey);
        SQLiteControlPlanePersistence.IdempotencyData candidate =
                new SQLiteControlPlanePersistence.IdempotencyData(scope, key, ControlPlaneHttpSupport.payloadHash(payload),
                        resultRef, resultJson, Instant.now(host.clock).toString());
        SQLiteControlPlanePersistence.IdempotencyData stored = host.store.persistIdempotency(candidate);
        if (!stored.payloadHash().equals(candidate.payloadHash())) {
            throw new ControlPlaneHttpSupport.ApiException(409, "IDEMPOTENCY_CONFLICT",
                    "Idempotency-Key was already used with a different request");
        }
        host.durableIdempotency.putIfAbsent(mapKey, stored);
        return stored;
    }
    ControlPlaneStore.ScanRecord latestScan(ControlPlaneStore.ProjectRecord project) {
        String id = project.latestScanId();
        return id == null ? null : host.store.scan(id);
    }
    Optional<ExperimentPlan> findAcceptedPlan(String scanId, String planId) {
        if (scanId == null || planId == null || planId.isBlank()) return Optional.empty();
        List<ExperimentPlan> plans = host.scanExperimentPlans.getOrDefault(scanId, List.of());
        return plans.stream().filter(plan -> planId.equals(plan.planId())).findFirst();
    }

    /**
     * D3 SQL experiment-card replay：复用 focus-probe 门禁与 card benign/meta 输入。
     * 永不升级为 VERIFIED；dependencyMode 经 focus 响应保持 MOCK 标签。
     */
    void publishEvent(String scanId, EventContext context, String type, String key,
                              Map<String, Object> payload) {
        // v1 仍包含 context，以便消费者收到必需的 project、artifact、scan 与 task 作用域标识符。
        VersionedEvent event = EventFactory.create(type, ApiDtos.EVENT_SCHEMA_VERSION, context,
                new IdempotencyKey("scan", scanId + ":" + type + ":" + key), JsonCodec.stringify(payload), host.clock);
        host.sseHub.publish(scanId, event);
    }
    static void mergeProviderBundleIntoScan(
            ProviderBundle bundle,
            String projectId,
            String artifactDigest,
            String scanId,
            String now,
            List<ApiDtos.EntryDto> entries,
            List<ApiDtos.SinkDto> sinks,
            Map<String, ApiDtos.EvidenceDto> evidence) {
        if (bundle == null) return;
        Set<String> entryIds = new LinkedHashSet<>();
        Set<String> entryRoutes = new LinkedHashSet<>();
        for (ApiDtos.EntryDto entry : entries) {
            entryIds.add(entry.id());
            entryRoutes.add(entryKey(entry.protocol(), entry.method(), entry.route()));
        }
        for (ProviderContribution.Entry contribution : bundle.entries()) {
            EntryNode node = contribution.node();
            if (node == null) continue;
            String entryId = stripPrefix(node.id(), "entry:");
            if (entryIds.contains(entryId)
                    || entryRoutes.contains(entryKey(node.protocol(), node.operation(), node.address()))) {
                continue;
            }
            List<String> refs = new ArrayList<>(node.evidenceRefs());
            ensureProviderEvidence(evidence, projectId, artifactDigest, scanId, now, refs,
                    contribution.providerId());
            entries.add(new ApiDtos.EntryDto(
                    ApiDtos.SCHEMA_VERSION, projectId, artifactDigest, scanId,
                    entryId, node.protocol(), node.operation(), node.address(),
                    node.declaringSymbol(), simpleName(node.declaringSymbol()),
                    node.inputs(), List.of(),
                    node.verificationStatus(), 0.7, 0, refs));
            entryIds.add(entryId);
        }
        Set<String> sinkIds = new LinkedHashSet<>();
        for (ApiDtos.SinkDto sink : sinks) {
            sinkIds.add(sink.id());
        }
        for (ProviderContribution.Effect contribution : bundle.effects()) {
            EffectNode node = contribution.node();
            if (node == null) continue;
            String sinkId = stripPrefix(node.id(), "effect:");
            if (sinkIds.contains(sinkId)) continue;
            List<String> refs = new ArrayList<>(node.evidenceRefs());
            ensureProviderEvidence(evidence, projectId, artifactDigest, scanId, now, refs,
                    contribution.providerId());
            sinks.add(new ApiDtos.SinkDto(
                    ApiDtos.SCHEMA_VERSION, projectId, artifactDigest, scanId,
                    sinkId, node.category(), node.symbol(), node.sourceLabel(),
                    node.verificationStatus(), 0.7, refs));
            sinkIds.add(sinkId);
        }
        for (ProviderContribution.Guard contribution : bundle.guards()) {
            GuardNode node = contribution.node();
            if (node == null) continue;
            if (!"AUTH_GAP".equalsIgnoreCase(node.guardKind())) continue;
            String sinkId = stripPrefix(node.id(), "guard:");
            if (sinkIds.contains(sinkId)) continue;
            List<String> refs = new ArrayList<>(node.evidenceRefs());
            ensureProviderEvidence(evidence, projectId, artifactDigest, scanId, now, refs,
                    contribution.providerId());
            sinks.add(new ApiDtos.SinkDto(
                    ApiDtos.SCHEMA_VERSION, projectId, artifactDigest, scanId,
                    sinkId, "AUTH_GAP", node.expression(), "provider-guard:" + contribution.providerId(),
                    ApiDtos.STATIC_INFERRED, 0.7, refs));
            sinkIds.add(sinkId);
        }
    }
    static void ensureProviderEvidence(
            Map<String, ApiDtos.EvidenceDto> evidence,
            String projectId,
            String artifactDigest,
            String scanId,
            String now,
            List<String> refs,
            String providerId) {
        if (refs == null) return;
        for (int i = 0; i < refs.size(); i++) {
            String ref = refs.get(i);
            if (ref == null || ref.isBlank()) continue;
            if (evidence.containsKey(ref)) continue;
            String id = ref.startsWith("evidence-") ? ref : "evidence-" + scanId + "-provider-" + ref;
            if (!evidence.containsKey(id)) {
                evidence.put(id, new ApiDtos.EvidenceDto(
                        ApiDtos.SCHEMA_VERSION, projectId, artifactDigest, scanId, id,
                        "INFERENCE", "provider:" + providerId + ":" + ref, 0.7,
                        "provider contribution evidence", now, "provider-spi/0.1",
                        "none", "artifact:" + artifactDigest, ApiDtos.MOCK));
            }
            refs.set(i, id);
        }
    }
    static String entryKey(String protocol, String method, String route) {
        return String.valueOf(protocol).toUpperCase(Locale.ROOT) + "|"
                + String.valueOf(method).toUpperCase(Locale.ROOT) + "|"
                + String.valueOf(route);
    }
    static String stripPrefix(String value, String prefix) {
        if (value == null) return "";
        return value.startsWith(prefix) ? value.substring(prefix.length()) : value;
    }
    static String sinkCategoryLabel(String category) {
        if (category == null || category.isBlank()) return "敏感调用";
        return switch (category.toUpperCase(Locale.ROOT)) {
            case "SSRF" -> "服务端请求伪造";
            case "DESERIALIZATION" -> "反序列化";
            case "COMMAND_EXECUTION", "RCE", "COMMAND" -> "命令执行";
            case "SQL_INJECTION", "SQLi", "SQL" -> "SQL 注入";
            case "JNDI" -> "JNDI 注入";
            case "XXE", "XML", "XSLT" -> "XML/XSLT 风险";
            case "PATH_TRAVERSAL", "FILE", "FILE_READ", "FILE_WRITE", "FILE_DELETE" -> "文件路径穿越";
            case "EXPRESSION", "SSTI", "TEMPLATE" -> "表达式/模板注入";
            case "REFLECTION", "CLASSLOADER", "CLASS_LOADING" -> "反射/类加载";
            case "JWT" -> "JWT/令牌处理";
            case "BPMN_DEPLOY" -> "BPMN/流程部署";
            case "BPMN_EXEC" -> "BPMN/流程执行";
            case "AUTH", "AUTH_GAP" -> "鉴权缺口";
            case "LDAP" -> "LDAP 注入";
            case "NOSQL" -> "NoSQL 注入";
            case "XPATH" -> "XPath 注入";
            case "NATIVE_CODE" -> "本地代码加载";
            case "REDIRECT" -> "开放重定向";
            case "ARCHIVE" -> "归档解压";
            default -> category;
        };
    }
    static String sinkDeclaringClass(ApiDtos.SinkDto sink) {
        int methodSeparator = sink.symbol().indexOf('#');
        return methodSeparator > 0 ? sink.symbol().substring(0, methodSeparator) : sink.symbol();
    }
    static String entryBindingKey(ApiDtos.EntryDto entry,
                                          Map<String, ApiDtos.EvidenceDto> evidence) {
        for (String ref : entry.evidenceRefs()) {
            ApiDtos.EvidenceDto item = evidence.get(ref);
            if (item != null && item.source().startsWith("classfile-annotation:")) {
                return item.source().substring("classfile-annotation:".length());
            }
        }
        return entry.declaringClass();
    }
    static String sinkBindingKey(ApiDtos.SinkDto sink,
                                         Map<String, ApiDtos.EvidenceDto> evidence) {
        for (String ref : sink.evidenceRefs()) {
            ApiDtos.EvidenceDto item = evidence.get(ref);
            if (item != null && item.source().startsWith("classfile-call:")) {
                String location = item.source().substring("classfile-call:".length());
                int descriptor = location.indexOf('(');
                return descriptor > 0 ? location.substring(0, descriptor) : location;
            }
        }
        return sinkDeclaringClass(sink);
    }
    static String staticSinkSeverity(String category, double confidence) {
        if (confidence < 0.80) return "low";
        return switch (category.toUpperCase(Locale.ROOT)) {
            case "COMMAND", "NATIVE_CODE", "CLASS_LOADING", "DESERIALIZATION",
                    "EXPRESSION", "TEMPLATE", "JNDI" -> "medium";
            case "SQL", "NOSQL", "LDAP", "XPATH", "XML", "XSLT", "SSRF",
                    "FILE_READ", "FILE_WRITE", "FILE_DELETE", "ARCHIVE", "REDIRECT",
                    "REFLECTION", "FILE", "JWT", "AUTH" -> "low";
            case "AUTH_GAP" -> "info";
            default -> "info";
        };
    }
    static List<String> prefixRefs(List<String> refs, Map<String, String> mapping) {
        List<String> result = new ArrayList<>();
        for (String ref : refs == null ? List.<String>of() : refs) result.add(mapping.getOrDefault(ref, ref));
        return List.copyOf(result);
    }
    static String simpleName(String className) {
        int index = Math.max(className.lastIndexOf('.'), className.lastIndexOf('/'));
        return index < 0 ? className : className.substring(index + 1);
    }
    static Map<String, Object> envelope(String projectId, List<Object> items) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        result.put("projectId", projectId);
        result.put("verificationStatus", ApiDtos.STATIC_INFERRED);
        result.put("dependencyMode", ApiDtos.MOCK);
        result.put("evidenceRefs", List.of());
        result.put("items", items);
        return result;
    }

    static Map<String, Object> envelope(ControlPlaneStore.ScanRecord scan, String key, List<Object> items) {
        Map<String, Object> result = new LinkedHashMap<>();
        ApiDtos.ScanDto dto = scan.dto();
        result.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest());
        result.put("scanId", dto.scanId());
        result.put("verificationStatus", dto.verificationStatus());
        result.put("dependencyMode", dto.dependencyMode());
        result.put("evidenceRefs", dto.evidenceRefs());
        result.put(key, items);
        result.put("items", items);
        return result;
    }
    static Map<String, Object> entryMap(ApiDtos.EntryDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest()); result.put("scanId", dto.scanId());
        result.put("id", dto.id()); result.put("protocol", dto.protocol()); result.put("method", dto.method());
        result.put("route", dto.route()); result.put("declaringClass", dto.declaringClass());
        result.put("module", dto.module()); result.put("parameters", dto.parameters());
        result.put("preconditions", dto.preconditions());
        result.put("precondition", dto.preconditions().isEmpty() ? "UNSPECIFIED" : dto.preconditions().get(0));
        result.put("verificationStatus", dto.verificationStatus()); result.put("status", dto.verificationStatus());
        result.put("dependencyMode", ApiDtos.MOCK);
        result.put("confidence", dto.confidence()); result.put("coverage", dto.coverage());
        result.put("evidenceRefs", dto.evidenceRefs());
        return result;
    }
    static Map<String, Object> dependencyMap(ApiDtos.DependencyDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest()); result.put("scanId", dto.scanId());
        result.put("id", dto.id()); result.put("kind", dto.kind()); result.put("target", dto.target());
        result.put("accessType", dto.accessType()); result.put("mode", dto.mode()); result.put("fields", dto.fields());
        result.put("verificationStatus", dto.verificationStatus()); result.put("status", dto.verificationStatus());
        result.put("confidence", dto.confidence()); result.put("evidenceRefs", dto.evidenceRefs());
        return result;
    }
    static Map<String, Object> sinkMap(ApiDtos.SinkDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest()); result.put("scanId", dto.scanId());
        result.put("id", dto.id()); result.put("category", dto.category()); result.put("symbol", dto.symbol());
        result.put("source", dto.source()); result.put("verificationStatus", dto.verificationStatus());
        result.put("status", dto.verificationStatus()); result.put("confidence", dto.confidence());
        result.put("evidenceRefs", dto.evidenceRefs());
        return result;
    }
    static Map<String, Object> evidenceMap(ApiDtos.EvidenceDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest()); result.put("scanId", dto.scanId());
        result.put("evidenceId", dto.evidenceId()); result.put("provenanceKind", dto.provenanceKind());
        result.put("kind", dto.provenanceKind()); result.put("source", dto.source());
        result.put("confidence", dto.confidence()); result.put("summary", dto.summary());
        result.put("verificationStatus", dto.verificationStatus());
        result.put("evidenceRefs", List.of(dto.evidenceId()));
        result.put("observedAt", dto.observedAt()); result.put("toolVersion", dto.toolVersion());
        result.put("modelVersion", dto.modelVersion()); result.put("snapshotRef", dto.snapshotRef());
        result.put("dependencyMode", dto.dependencyMode());
        return result;
    }
    static Map<String, Object> findingMap(ApiDtos.FindingDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest()); result.put("scanId", dto.scanId());
        result.put("findingId", dto.findingId()); result.put("id", dto.findingId()); result.put("title", dto.title());
        result.put("severity", dto.severity()); result.put("verificationStatus", dto.verificationStatus());
        result.put("status", dto.verificationStatus()); result.put("entrypointId", dto.entrypointId());
        result.put("entry", dto.entry()); result.put("sinkId", dto.sinkId()); result.put("sink", dto.sink());
        result.put("dependency", dto.dependency()); result.put("dependencyRefs", dto.dependencyRefs());
        result.put("evidenceRefs", dto.evidenceRefs()); result.put("evidenceCount", dto.evidenceCount());
        result.put("evidence", dto.evidenceCount()); result.put("confidence", dto.confidence());
        result.put("dependencyMode", dto.dependencyMode());
        if (dto.hypothesisId() != null && !dto.hypothesisId().isBlank()) {
            result.put("hypothesisId", dto.hypothesisId());
        }
        if (dto.securityProperty() != null && !dto.securityProperty().isBlank()) {
            result.put("securityProperty", dto.securityProperty());
        }
        if (dto.rootCause() != null && !dto.rootCause().isEmpty()) {
            result.put("rootCause", dto.rootCause());
        }
        return result;
    }
    static List<Object> hypothesisMaps(List<SecurityHypothesis> hypotheses) {
        List<Object> items = new ArrayList<>();
        for (SecurityHypothesis hypothesis : hypotheses == null ? List.<SecurityHypothesis>of() : hypotheses) {
            items.add(hypothesis.toMap());
        }
        return items;
    }
    static Map<String, Object> pathStepMap(ApiDtos.PathStepDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("label", dto.label()); result.put("detail", dto.detail()); result.put("kind", dto.kind());
        result.put("state", dto.state()); result.put("evidenceRefs", dto.evidenceRefs());
        result.put("verificationStatus", dto.verificationStatus());
        result.put("provenanceKind", dto.provenanceKind());
        result.put("eventType", dto.eventType());
        if (dto.sequence() != null) result.put("sequence", dto.sequence());
        return result;
    }
    static Map<String, Object> pathMap(ApiDtos.PathDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest()); result.put("scanId", dto.scanId());
        result.put("pathId", dto.pathId()); result.put("entrypointId", dto.entrypointId());
        result.put("verificationStatus", dto.verificationStatus()); result.put("status", dto.verificationStatus());
        result.put("dependencyMode", dto.dependencyMode()); result.put("preconditions", dto.preconditions());
        result.put("stopReason", dto.stopReason()); result.put("evidenceRefs", dto.evidenceRefs());
        if (dto.taskId() != null) {
            result.put("taskId", dto.taskId());
            result.put("fixtureOnly", dto.fixtureOnly());
            result.put("requiredCapability", dto.requiredCapability());
            result.put("dynamicExecutionMode", dto.dynamicExecutionMode());
        }
        List<Object> steps = new ArrayList<>(); for (ApiDtos.PathStepDto step : dto.steps()) steps.add(pathStepMap(step));
        result.put("steps", steps); result.put("path", steps);
        return result;
    }
    static Map<String, Object> pathRunMap(ApiDtos.PathRunDto dto) {
        return PathDebugWireHelper.basePathRunMap(dto);
    }
    static String correlationIdFromPathRun(ApiDtos.PathRunDto dto) {
        if (dto == null) return "";
        String attempt = dto.attemptId() == null ? "" : dto.attemptId().trim();
        if (attempt.startsWith("req-") && attempt.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")) {
            return attempt;
        }
        String summary = dto.requestSummary() == null ? "" : dto.requestSummary();
        int marker = summary.indexOf("correlationId=");
        if (marker < 0) return "";
        String rest = summary.substring(marker + "correlationId=".length()).trim();
        int end = rest.indexOf(' ');
        String value = end < 0 ? rest : rest.substring(0, end);
        return value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,63}") ? value : "";
    }
    static Map<String, Object> scanMap(ApiDtos.ScanDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest()); result.put("scanId", dto.scanId());
        result.put("status", dto.status()); result.put("verificationStatus", dto.verificationStatus());
        result.put("dependencyMode", dto.dependencyMode()); result.put("createdAt", dto.createdAt());
        result.put("completedAt", dto.completedAt()); result.put("evidenceRefs", dto.evidenceRefs());
        List<Object> entries = new ArrayList<>(); for (ApiDtos.EntryDto x : dto.entries()) entries.add(entryMap(x));
        List<Object> deps = new ArrayList<>(); for (ApiDtos.DependencyDto x : dto.dependencies()) deps.add(dependencyMap(x));
        List<Object> sinks = new ArrayList<>(); for (ApiDtos.SinkDto x : dto.sinks()) sinks.add(sinkMap(x));
        List<Object> findings = new ArrayList<>(); for (ApiDtos.FindingDto x : dto.findings()) findings.add(findingMap(x));
        List<Object> paths = new ArrayList<>(); for (ApiDtos.PathDto x : dto.paths()) paths.add(pathMap(x));
        result.put("entries", entries); result.put("entryCatalog", entries); result.put("dependencies", deps);
        result.put("dependencyMap", deps); result.put("sinks", sinks); result.put("sinkCatalog", sinks);
        result.put("findings", findings); result.put("paths", paths);
        return result;
    }
    static Map<String, Object> chainMap(ApiDtos.AttackChainDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactDigest", dto.artifactDigest()); result.put("scanId", dto.scanId());
        result.put("chainId", dto.chainId()); result.put("id", dto.chainId()); result.put("title", dto.title());
        result.put("confidence", dto.confidence()); result.put("verificationStatus", dto.verificationStatus());
        result.put("status", dto.verificationStatus()); result.put("findingRefs", dto.findingRefs());
        result.put("evidenceRefs", dto.evidenceRefs());
        return result;
    }
    static Map<String, Object> stringEnvelope(String key, Object value) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", ApiDtos.SCHEMA_VERSION); result.put(key, value); return result;
    }
void releaseRetainedSandboxForScan(String scanId) {
        try {
            ControlPlaneStore.ScanRecord scan = host.store.requireScan(scanId);
            host.retainedSandboxRelease.release(
                    scan.dto().projectId(), scan.dto().artifactDigest(), scanId);
        } catch (RuntimeException ignored) {
            // 尽力而为；scan 拆除或外部回调不得阻塞 pipeline CAS。
        }
    }
}

package com.aq.jvmsentinel.ai.memory;

import com.aq.jvmsentinel.analysis.contrast.ContrastLedger;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.model.ContrastStatus;
import com.aq.jvmsentinel.provider.AgentRole;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * 构建同 scan 共享 memory 快照，供 AI 角色与 GUI 调试视图。
 * 仅服务端编写；模型不能写入 FACT 层。
 */
public final class ScanMemoryBuilder {
    public static final int SCHEMA_VERSION = 1;
    private static final int MAX_INDEX = 48;
    private static final int MAX_INFERENCE = 8;

    private ScanMemoryBuilder() {
    }

    public static Map<String, Object> build(
            ControlPlaneStore store,
            String scanId,
            List<ApiDtos.PathRunDto> pathRuns,
            Map<String, String> priorRoleSummaries) {
        Objects.requireNonNull(store, "store");
        Objects.requireNonNull(scanId, "scanId");
        ControlPlaneStore.ScanRecord scan = store.requireScan(scanId);
        ApiDtos.ScanDto dto = scan.dto();
        List<ApiDtos.PathRunDto> runs = pathRuns == null ? List.of() : pathRuns;

        List<Map<String, Object>> authWalls = new ArrayList<>();
        List<Map<String, Object>> gatePasses = new ArrayList<>();
        List<Map<String, Object>> knownEffects = new ArrayList<>();
        List<Map<String, Object>> forcedNotes = new ArrayList<>();
        int forced2xx = 0;
        int unauthChallenge = 0;
        for (ApiDtos.PathRunDto run : runs) {
            if (run == null) {
                continue;
            }
            String track = run.track() == null ? "" : run.track().toUpperCase(Locale.ROOT);
            String outcome = run.outcomeClass() == null ? "" : run.outcomeClass().toUpperCase(Locale.ROOT);
            if ("AUTH_CHALLENGE".equals(outcome)) {
                unauthChallenge++;
                if (authWalls.size() < MAX_INDEX) {
                    authWalls.add(pathRunIndexRow(run, "AUTH_WALL"));
                }
            }
            if (track.contains("FORCED") && run.httpStatus() >= 200 && run.httpStatus() < 400) {
                forced2xx++;
                if (forcedNotes.size() < MAX_INDEX) {
                    forcedNotes.add(pathRunIndexRow(run, "FORCED_PASS"));
                }
            }
            if ((track.contains("BYPASS") || "ADMIN".equals(track) || track.contains("COVERAGE"))
                    && run.httpStatus() >= 200 && run.httpStatus() < 400
                    && Boolean.TRUE.equals(run.entryHit())
                    && gatePasses.size() < MAX_INDEX) {
                gatePasses.add(pathRunIndexRow(run, "GATE_PASS"));
            }
            PathTrace trace = store.pathTraceForPathRun(run.pathRunId());
            if (trace != null && trace.effectRefs() != null) {
                for (String effectRef : trace.effectRefs()) {
                    if (effectRef == null || effectRef.isBlank() || knownEffects.size() >= MAX_INDEX) {
                        continue;
                    }
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("pathRunId", run.pathRunId());
                    row.put("entry", run.entrypointRef());
                    row.put("track", run.track());
                    row.put("effectRef", effectRef);
                    row.put("lastBusinessHop", trace.lastBusinessHop());
                    row.put("note", "RUNTIME_OBSERVED; FORCED≠VERIFIED");
                    knownEffects.add(row);
                }
            }
        }

        List<Map<String, Object>> staticOnlyGaps = new ArrayList<>();
        ContrastLedger.Ledger ledger = ContrastLedger.build(
                dto.entries(),
                dto.sinks(),
                scan.evidence(),
                runs,
                StaticFactSnapshot.resolveTaintPaths(store.staticFacts(scanId), dto.sinks()));
        for (var row : ledger.rows()) {
            if (row == null || row.contrastStatus() != ContrastStatus.STATIC_ONLY) {
                continue;
            }
            if (staticOnlyGaps.size() >= MAX_INDEX) {
                break;
            }
            Map<String, Object> gap = new LinkedHashMap<>();
            gap.put("sinkId", row.sinkId());
            gap.put("category", row.category());
            gap.put("sinkSymbol", trim(row.sinkSymbol(), 160));
            gap.put("entryRefs", row.entryRefs());
            gap.put("contrastStatus", row.contrastStatus().name());
            gap.put("stopReason", trim(row.stopReason(), 160));
            staticOnlyGaps.add(gap);
        }

        List<Map<String, Object>> candidateHyps = new ArrayList<>();
        List<Map<String, Object>> supportedHyps = new ArrayList<>();
        for (SecurityHypothesis hyp : store.hypotheses(scanId)) {
            if (hyp == null) {
                continue;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("hypothesisId", hyp.hypothesisId());
            row.put("family", hyp.family() == null ? "" : hyp.family().name());
            row.put("lifecycle", hyp.lifecycle() == null ? "" : hyp.lifecycle().name());
            row.put("securityProperty", trim(hyp.securityProperty(), 160));
            row.put("source", trim(hyp.source(), 120));
            row.put("effect", trim(hyp.effect(), 120));
            if (hyp.lifecycle() == HypothesisLifecycle.CANDIDATE && candidateHyps.size() < MAX_INDEX) {
                candidateHyps.add(row);
            } else if (hyp.lifecycle() == HypothesisLifecycle.SUPPORTED && supportedHyps.size() < MAX_INDEX) {
                supportedHyps.add(row);
            }
        }

        List<Map<String, Object>> entryIndex = new ArrayList<>();
        for (ApiDtos.EntryDto entry : dto.entries()) {
            if (entry == null || entryIndex.size() >= MAX_INDEX) {
                break;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("entryId", entry.id());
            row.put("method", entry.method());
            row.put("route", entry.route());
            row.put("preconditions", entry.preconditions());
            entryIndex.add(row);
        }

        List<Map<String, Object>> sinkIndex = new ArrayList<>();
        for (ApiDtos.SinkDto sink : dto.sinks()) {
            if (sink == null || sinkIndex.size() >= MAX_INDEX) {
                break;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("sinkId", sink.id());
            row.put("category", sink.category());
            row.put("symbol", trim(sink.symbol(), 160));
            sinkIndex.add(row);
        }

        List<Map<String, Object>> inferences = new ArrayList<>();
        if (priorRoleSummaries != null) {
            for (Map.Entry<String, String> item : priorRoleSummaries.entrySet()) {
                if (item.getKey() == null || item.getValue() == null || item.getValue().isBlank()) {
                    continue;
                }
                if (inferences.size() >= MAX_INFERENCE) {
                    break;
                }
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("role", item.getKey());
                row.put("layer", "INFERENCE");
                row.put("summary", trim(item.getValue(), 800));
                row.put("note", "不可升 VERIFIED / 不可改写 FACT");
                inferences.add(row);
            }
        }

        Map<String, Object> counts = new LinkedHashMap<>();
        counts.put("entries", dto.entries().size());
        counts.put("sinks", dto.sinks().size());
        counts.put("pathRuns", runs.size());
        counts.put("authWallSamples", authWalls.size());
        counts.put("gatePassSamples", gatePasses.size());
        counts.put("knownEffects", knownEffects.size());
        counts.put("staticOnlyGaps", staticOnlyGaps.size());
        counts.put("candidateHypotheses", candidateHyps.size());
        counts.put("forced2xxPathRuns", forced2xx);
        counts.put("unauthChallengePathRuns", unauthChallenge);

        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("entryIndex", entryIndex);
        facts.put("sinkIndex", sinkIndex);
        facts.put("authWallEntries", authWalls);
        facts.put("gatePassEntries", gatePasses);
        facts.put("knownEffects", knownEffects);
        facts.put("forcedReachabilityNotes", forcedNotes);

        Map<String, Object> work = new LinkedHashMap<>();
        work.put("staticOnlyGaps", staticOnlyGaps);
        work.put("candidateHypotheses", candidateHyps);
        work.put("supportedHypotheses", supportedHyps);

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("schemaVersion", SCHEMA_VERSION);
        root.put("projectId", dto.projectId());
        root.put("artifactDigest", dto.artifactDigest());
        root.put("scanId", scanId);
        root.put("builtAt", Instant.now().toString());
        root.put("layerRules", Map.of(
                "FACTS", "控制面/动态写入；AI 可引用",
                "WORK", "待验证假设与 STATIC_ONLY 缺口；AI 可引用",
                "INFERENCE", "角色结论摘要；不可单独升验证等级"));
        root.put("counts", counts);
        root.put("facts", facts);
        root.put("work", work);
        root.put("inference", inferences);
        root.put("toolsCatalog", toolsCatalog());
        root.put("roleSlices", roleSliceHints());
        return root;
    }

    /** 供 prompt 注入的紧凑 INDEX 分区。 */
    public static Map<String, Object> indexOnly(Map<String, Object> full) {
        Map<String, Object> index = new LinkedHashMap<>();
        index.put("schemaVersion", full.get("schemaVersion"));
        index.put("scanId", full.get("scanId"));
        index.put("builtAt", full.get("builtAt"));
        index.put("counts", full.get("counts"));
        index.put("layerRules", full.get("layerRules"));
        @SuppressWarnings("unchecked")
        Map<String, Object> facts = (Map<String, Object>) full.get("facts");
        @SuppressWarnings("unchecked")
        Map<String, Object> work = (Map<String, Object>) full.get("work");
        if (facts != null) {
            index.put("knownEffects", facts.get("knownEffects"));
            index.put("authWallEntries", limitList(facts.get("authWallEntries"), 12));
            index.put("forcedReachabilityNotes", limitList(facts.get("forcedReachabilityNotes"), 12));
        }
        if (work != null) {
            index.put("staticOnlyGaps", limitList(work.get("staticOnlyGaps"), 16));
            index.put("candidateHypotheses", limitList(work.get("candidateHypotheses"), 16));
        }
        index.put("howToDeepen", List.of(
                "scan_memory_get section=FACTS|WORK|INFERENCE|TOOLS_CATALOG|ROLE_SLICE",
                "facts_search kind=PATH_RUN|PATH_TRACE|STATIC_CONTRAST|SINK|ENTRY",
                "code_query kind=METHOD_VIEW|GUARD_QUERY|DATAFLOW_SLICE|AUTH",
                "evidence_get evidenceRef=...",
                "sandbox_probe 仅 DYNAMIC/PATH/TRIAGE 角色且服务端闸门"));
        return index;
    }

    public static Map<String, Object> section(Map<String, Object> full, String sectionName) {
        String section = sectionName == null ? "INDEX" : sectionName.trim().toUpperCase(Locale.ROOT);
        return switch (section) {
            case "FACTS" -> mapOrEmpty(full.get("facts"));
            case "WORK" -> mapOrEmpty(full.get("work"));
            case "INFERENCE" -> Map.of("inference", full.getOrDefault("inference", List.of()));
            case "TOOLS_CATALOG" -> Map.of("toolsCatalog", full.getOrDefault("toolsCatalog", List.of()));
            case "ROLE_SLICE" -> Map.of("roleSlices", full.getOrDefault("roleSlices", Map.of()));
            case "FULL" -> full;
            default -> indexOnly(full);
        };
    }

    public static Map<String, Object> roleSlice(Map<String, Object> full, AgentRole role) {
        Map<String, Object> slice = new LinkedHashMap<>();
        slice.put("role", role == null ? "" : role.name());
        slice.put("index", indexOnly(full));
        @SuppressWarnings("unchecked")
        Map<String, Object> hints = (Map<String, Object>) full.get("roleSlices");
        if (hints != null && role != null) {
            slice.put("guidance", hints.get(role.name()));
        }
        return slice;
    }

    private static List<Map<String, Object>> toolsCatalog() {
        List<Map<String, Object>> tools = new ArrayList<>();
        tools.add(tool("scan_memory_get",
                "读取本扫描共享记忆切片",
                "section=INDEX|FACTS|WORK|INFERENCE|TOOLS_CATALOG|ROLE_SLICE|FULL；INDEX 已在提示词则跳过；"
                        + "ROLE_SLICE 时可选 role=（默认当前任务角色，不能改权限）",
                "索引、事实层、工作层、推断层、工具说明、角色切片",
                "全部六个角色"));
        tools.add(tool("facts_search",
                "在已索引事实中搜索",
                "kind=SCAN|ENTRY|DEPENDENCY|SINK|…；query 用 entryId/route/class（勿用 * 或单空格；空 query=列表）；limit",
                "入口/依赖/sink/证据/PathRun 摘要/PathTrace 参数流与 effect/对照行",
                "全部角色（按白名单）"));
        tools.add(tool("evidence_get",
                "按证据引用读一条证据",
                "evidenceRef=",
                "单条证据正文与 provenance",
                "全部角色"));
        tools.add(tool("code_query",
                "只读代码/鉴权/配置查询",
                "kind=METHOD_VIEW|CALLERS|CALLEES|CFG_VIEW|DATAFLOW_SLICE|GUARD_QUERY|FIELD_USES|CONFIG_SEARCH|AUTH；query；limit",
                "方法切片、调用关系、CFG、污点切片、guard、配置/JWT 材料（脱敏）",
                "PRE/AUTH/PATH/TRIAGE"));
        tools.add(tool("plan_propose",
                "提出非执行实验/绕过候选计划",
                "entrypointRef、objective、techniqueId、authorizationHeader 等",
                "服务端落库的候选计划（不直接改沙箱策略）",
                "AUTH/DYNAMIC/PATH/TRIAGE/REPORT"));
        tools.add(tool("sandbox_probe",
                "在授权沙箱内有界探针",
                "entrypointRef、candidateInputs、techniqueId、authorizationHeader",
                "新的 PathRun/PathTrace 事实（loopback；不能改命令/挂载/网络/UID/预算）",
                "DYNAMIC/PATH/TRIAGE"));
        tools.add(tool("fuzz_strategy_get",
                "读取服务端模糊/验证策略提示",
                "无或少量参数",
                "动态验证策略说明",
                "DYNAMIC_VERIFICATION"));
        return tools;
    }

    private static Map<String, Object> roleSliceHints() {
        Map<String, Object> hints = new LinkedHashMap<>();
        hints.put(AgentRole.PRE_ANALYSIS.name(),
                "必读：entryIndex/sinkIndex/覆盖缺口；用 code_query/facts_search 深挖；不要假设已有 PathRun。");
        hints.put(AgentRole.AUTH_ANALYSIS.name(),
                "必读：authWall/配置类假设；用 GUARD_QUERY/AUTH；PoC 用 plan_propose；勿把 FORCED 写成已绕过。");
        hints.put(AgentRole.DYNAMIC_VERIFICATION.name(),
                "必读：gatePass/绕过候选；必须 sandbox_probe；用 PATH_RUN 核对。");
        hints.put(AgentRole.PATH_EXPLORATION.name(),
                "必读：staticOnlyGaps/candidateHypotheses/knownEffects；定向 sandbox_probe；FORCED 仅 INSTRUMENTATION。");
        hints.put(AgentRole.VULNERABILITY_TRIAGE.name(),
                "必读：supported+candidate、对照缺口、knownEffects；延迟组链；仅 SQL H3 可 DYNAMIC_CONFIRMED。");
        hints.put(AgentRole.REPORT_GENERATION.name(),
                "必读：counts、staticOnlyGaps、knownEffects、inference；主漏洞在上、风险点在下；勿堆工具原始 JSON。");
        return hints;
    }

    private static Map<String, Object> tool(String name, String purposeZh, String argsZh,
                                            String returnsZh, String rolesZh) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", name);
        row.put("purposeZh", purposeZh);
        row.put("argsZh", argsZh);
        row.put("returnsZh", returnsZh);
        row.put("rolesZh", rolesZh);
        return row;
    }

    private static Map<String, Object> pathRunIndexRow(ApiDtos.PathRunDto run, String kind) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("kind", kind);
        row.put("pathRunId", run.pathRunId());
        row.put("entry", run.entrypointRef());
        row.put("track", run.track());
        row.put("httpStatus", run.httpStatus());
        row.put("outcomeClass", run.outcomeClass());
        row.put("entryHit", run.entryHit());
        return row;
    }

    private static String trim(String value, int max) {
        if (value == null) {
            return "";
        }
        String text = value.trim();
        return text.length() <= max ? text : text.substring(0, max);
    }

    @SuppressWarnings("unchecked")
    private static List<?> limitList(Object value, int max) {
        if (!(value instanceof List<?> list) || list.isEmpty()) {
            return List.of();
        }
        return list.size() <= max ? list : list.subList(0, max);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mapOrEmpty(Object value) {
        if (value instanceof Map<?, ?> map) {
            return new LinkedHashMap<>((Map<String, Object>) map);
        }
        return Map.of();
    }
}

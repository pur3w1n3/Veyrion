package com.aq.jvmsentinel.ai.tool;

import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.OutputKind;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolCall;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolOutput;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus;
import com.aq.jvmsentinel.ai.AuthBypassFeasibility;
import com.aq.jvmsentinel.analysis.fuzz.FuzzStrategyRegistry;
import com.aq.jvmsentinel.domain.experiment.ExperimentPlanKind;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.worker.ExperimentPlanValidator;
import com.aq.jvmsentinel.worker.HypothesisExperimentPlanValidator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * 代码拥有的 registry 与 fail-closed 分发器。Provider 适配器可暴露
 * {@link #definitionsFor(AgentRole)}，但不能注册 handler 或改变 role 授权。
 */
public final class AiToolRegistry {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Set<String> RESERVED_ARGUMENT_NAMES = Set.of(
            "permission", "permissions", "approved", "authorized", "network", "sandbox",
            "tenantoverride", "tenant", "workspace", "workspaceid", "project", "projectid",
            "principal", "principalid", "job", "jobid", "role", "allowlist", "deadline",
            "maxcalls", "maxresultbytes");

    private final ToolDataSource source;
    private final Map<String, RegisteredTool> tools;

    public AiToolRegistry(ToolDataSource source) {
        this.source = Objects.requireNonNull(source, "source");
        Map<String, RegisteredTool> fixed = new LinkedHashMap<>();
        add(fixed, factsSearch());
        add(fixed, evidenceGet());
        add(fixed, codeQuery());
        add(fixed, planPropose());
        add(fixed, sandboxProbe());
        add(fixed, fuzzStrategyGet());
        add(fixed, scanMemoryGet());
        this.tools = Map.copyOf(fixed);
    }

    public List<ToolDefinition> definitionsFor(AgentRole role) {
        Objects.requireNonNull(role, "role");
        Set<String> allowlist = ToolExecutionContext.bind(
                new ToolExecutionContext.Scope("definition", "definition"),
                "definition", "definition", role,
                new ToolExecutionContext.Budget(1, 2, 1, 64, java.time.Instant.MAX))
                .allowedTools();
        return tools.values().stream()
                .filter(tool -> allowlist.contains(tool.definition().name()))
                .map(RegisteredTool::definition)
                .toList();
    }

    public ToolResult execute(ToolCall call, ToolExecutionContext context) {
        Objects.requireNonNull(call, "call");
        Objects.requireNonNull(context, "context");
        if (context.isCancelled()) return CanonicalToolContracts.error(call, ToolStatus.CANCELLED, "JOB_CANCELLED");
        if (context.expired()) return CanonicalToolContracts.error(call, ToolStatus.TIMEOUT, "DEADLINE_EXCEEDED");
        if (!context.consumeCall()) {
            return CanonicalToolContracts.error(call, ToolStatus.NOT_EXECUTED, "CALL_BUDGET_EXHAUSTED");
        }

        RegisteredTool tool = tools.get(call.toolName());
        if (tool == null) return CanonicalToolContracts.error(call, ToolStatus.NOT_FOUND, "UNKNOWN_TOOL");
        if (!context.allowedTools().contains(call.toolName())) {
            return CanonicalToolContracts.error(call, ToolStatus.DENIED, "TOOL_NOT_ALLOWED_FOR_ROLE");
        }
        if (exceedsJsonDepth(call.arguments(), context.budget().maxJsonDepth())) {
            return CanonicalToolContracts.error(call, ToolStatus.INVALID_ARGUMENTS, "ARGUMENT_DEPTH_EXCEEDED");
        }

        byte[] encoded;
        try {
            encoded = JSON.writeValueAsBytes(call.arguments());
        } catch (Exception exception) {
            return CanonicalToolContracts.error(call, ToolStatus.INVALID_ARGUMENTS, "ARGUMENT_ENCODING_FAILED");
        }
        if (encoded.length > context.budget().maxArgumentBytes()) {
            return CanonicalToolContracts.error(call, ToolStatus.INVALID_ARGUMENTS, "ARGUMENT_BYTES_EXCEEDED");
        }
        // 已声明 schema 字段（如 scan_memory_get.role 用于 ROLE_SLICE）允许；
        // 未声明保留名仍表示模型控制的 scope/authority。
        if (containsReservedName(call.arguments(), tool.schema().fields().keySet())) {
            return CanonicalToolContracts.error(call, ToolStatus.DENIED, "MODEL_CONTROLLED_SCOPE_OR_AUTHORITY");
        }
        String schemaError = tool.schema().validate(call.arguments());
        if (schemaError != null) {
            return CanonicalToolContracts.error(call, ToolStatus.INVALID_ARGUMENTS, schemaError);
        }

        try {
            List<ToolOutput> outputs = tool.handler().execute(call, context);
            if (context.isCancelled()) {
                return CanonicalToolContracts.error(call, ToolStatus.CANCELLED, "JOB_CANCELLED");
            }
            if (context.expired()) {
                return CanonicalToolContracts.error(call, ToolStatus.TIMEOUT, "DEADLINE_EXCEEDED");
            }
            return fitResult(call, outputs, context.budget().maxResultBytes(), tool.definition().overflowPolicy());
        } catch (MissingException exception) {
            return CanonicalToolContracts.error(call, ToolStatus.NOT_FOUND, exception.code);
        } catch (ScopeException exception) {
            return CanonicalToolContracts.error(call, ToolStatus.DENIED, "DATA_SOURCE_SCOPE_MISMATCH");
        } catch (SecurityException exception) {
            return CanonicalToolContracts.error(call, ToolStatus.DENIED, "DATA_SOURCE_SECURITY_DENIED");
        } catch (IllegalArgumentException exception) {
            String code = argumentErrorCode(exception);
            if (EntryRefResolver.CODE_NOT_FOUND.equals(code)) {
                return CanonicalToolContracts.error(call, ToolStatus.NOT_FOUND, code);
            }
            return CanonicalToolContracts.error(call, ToolStatus.INVALID_ARGUMENTS, code);
        } catch (Exception exception) {
            return CanonicalToolContracts.error(call, ToolStatus.FAILED, "TOOL_EXECUTION_FAILED");
        }
    }

    private ToolResult fitResult(ToolCall call, List<ToolOutput> outputs, int maximum, OverflowPolicy policy)
            throws Exception {
        List<ToolOutput> immutable = List.copyOf(outputs);
        if (resultBytes(call, immutable, false) <= maximum) {
            return new ToolResult(CanonicalToolContracts.SCHEMA_VERSION, call.callId(), call.toolName(),
                    ToolStatus.SUCCESS, immutable, null, false);
        }
        if (policy == OverflowPolicy.DENY) {
            return CanonicalToolContracts.error(call, ToolStatus.NOT_EXECUTED, "RESULT_BYTES_EXCEEDED");
        }
        List<ToolOutput> fitted = new ArrayList<>();
        for (ToolOutput output : immutable) {
            List<ToolOutput> candidate = new ArrayList<>(fitted);
            candidate.add(output);
            if (resultBytes(call, candidate, true) > maximum) break;
            fitted.add(output);
        }
        if (resultBytes(call, fitted, true) > maximum) {
            return CanonicalToolContracts.error(call, ToolStatus.NOT_EXECUTED, "RESULT_BYTES_EXCEEDED");
        }
        return new ToolResult(CanonicalToolContracts.SCHEMA_VERSION, call.callId(), call.toolName(),
                ToolStatus.SUCCESS, fitted, null, true);
    }

    private int resultBytes(ToolCall call, List<ToolOutput> outputs, boolean truncated) throws Exception {
        ToolResult result = new ToolResult(CanonicalToolContracts.SCHEMA_VERSION, call.callId(), call.toolName(),
                ToolStatus.SUCCESS, outputs, null, truncated);
        return JSON.writeValueAsBytes(result).length;
    }

    private RegisteredTool scanMemoryGet() {
        Map<String, Field> fields = new LinkedHashMap<>();
        fields.put("section", Field.string(32));
        fields.put("role", Field.string(64));
        ToolSchema schema = new ToolSchema(Map.copyOf(fields), Set.of());
        ToolDefinition definition = new ToolDefinition("scan_memory_get",
                "Read the same-scan shared memory snapshot (server-authored). "
                        + "section=INDEX|FACTS|WORK|INFERENCE|TOOLS_CATALOG|ROLE_SLICE|FULL (default INDEX). "
                        + "If SCAN_MEMORY_INDEX is already in the prompt, skip INDEX and read FACTS/WORK/TOOLS_CATALOG. "
                        + "Optional role= only for ROLE_SLICE (defaults to the current job role; do not use role to "
                        + "change job authority). FACTS/WORK are citable; INFERENCE must not upgrade VERIFIED. "
                        + "Does not change sandbox policy.",
                schema.jsonSchema(), OverflowPolicy.TRUNCATE);
        return new RegisteredTool(definition, schema, (call, context) -> {
            String section = call.arguments().has("section")
                    ? call.arguments().get("section").asText("INDEX") : "INDEX";
            String role = call.arguments().has("role")
                    ? call.arguments().get("role").asText("") : context.role().name();
            ToolDataSource.FactRecord record = source.getScanMemory(context.scope(), section, role)
                    .orElseThrow(() -> new MissingException("SCAN_MEMORY_UNAVAILABLE"));
            requireScope(context, record);
            return List.of(new ToolOutput(OutputKind.FACT, record.reference(), record.value()));
        });
    }

    private RegisteredTool factsSearch() {
        ToolSchema schema = new ToolSchema(
                Map.of("kind", Field.string(64), "query", Field.string(1024), "limit", Field.integer(1, 100)),
                Set.of("kind"));
        ToolDefinition definition = new ToolDefinition("facts_search",
                "Search already-indexed, read-only facts in the server-bound project. "
                        + "Prefer scan_memory_get section=FACTS (or INDEX only if not already injected) before flooding. "
                        + "Kinds: SCAN, ENTRY, DEPENDENCY, SINK, EVIDENCE, DYNAMIC_EVIDENCE, PATH_RUN, PATH_TRACE, "
                        + "STATIC_CONTRAST, ANY. "
                        + "Omit query or use \"\" to list up to limit; never use \"*\" or a lone space (substring miss → empty). "
                        + "For PRE_ANALYSIS, query ENTRY with entry ids, routes, controller/class names, HTTP methods, "
                        + "or English enum keywords; do not rely only on translated prose. "
                        + "PATH_RUN returns persisted HTTP status, outcomeClass, and SQL event detail. "
                        + "PATH_TRACE returns parameter flow, last business hop, effects, and exit reason. "
                        + "Policy override fields (command/image/mount/network/uid/budget/forcedReachability) are rejected. "
                        + "STATIC_CONTRAST returns sink-perspective static↔PathRun contrast rows "
                        + "(MATCHED/PARTIAL/STATIC_ONLY/DYNAMIC_ONLY); STATIC_ONLY is never bypass-confirmed.",
                schema.jsonSchema(), OverflowPolicy.TRUNCATE);
        return new RegisteredTool(definition, schema, (call, context) -> {
            JsonNode args = call.arguments();
            String kind = args.get("kind").asText();
            String query = args.has("query") ? args.get("query").asText() : "";
            int limit = args.has("limit") ? args.get("limit").asInt() : 50;
            List<ToolDataSource.FactRecord> records = source.searchFacts(context.scope(), kind, query, limit);
            if (records == null || records.size() > limit) throw new IllegalStateException("invalid data source result");
            List<ToolOutput> outputs = new ArrayList<>();
            for (ToolDataSource.FactRecord record : records) {
                requireScope(context, record);
                outputs.add(new ToolOutput(OutputKind.FACT, record.reference(), record.value()));
            }
            return outputs;
        });
    }

    private RegisteredTool evidenceGet() {
        ToolSchema schema = new ToolSchema(Map.of("evidenceRef", Field.string(1024)), Set.of("evidenceRef"));
        ToolDefinition definition = new ToolDefinition("evidence_get",
                "Read one existing evidence item from the server-bound project.",
                schema.jsonSchema(), OverflowPolicy.DENY);
        return new RegisteredTool(definition, schema, (call, context) -> {
            ToolDataSource.FactRecord record = source.findEvidence(
                    context.scope(), call.arguments().get("evidenceRef").asText())
                    .orElseThrow(() -> new MissingException("EVIDENCE_NOT_FOUND"));
            requireScope(context, record);
            return List.of(new ToolOutput(OutputKind.FACT, record.reference(), record.value()));
        });
    }

    private RegisteredTool codeQuery() {
        Map<String, Field> fields = new LinkedHashMap<>();
        fields.put("kind", Field.string(64));
        fields.put("query", Field.string(1024));
        fields.put("limit", Field.integer(1, 50));
        ToolSchema schema = new ToolSchema(Map.copyOf(fields), Set.of());
        ToolDefinition definition = new ToolDefinition("code_query",
                "Bounded read-only code/auth/config query over persisted static facts and the "
                        + "registered artifact. Optional kind selects a versioned projection: "
                        + "METHOD_VIEW, CALLERS, CALLEES, CFG_VIEW, DATAFLOW_SLICE, GUARD_QUERY, "
                        + "FIELD_USES, CONFIG_SEARCH, AUTH (legacy string/config harvest), "
                        + "TAINT_GRAPH (legacy alias of DATAFLOW_SLICE). "
                        + "Blank kind defaults to AUTH/CONFIG_SEARCH harvest. "
                        + "AUTH_ANALYSIS should prefer METHOD_VIEW / GUARD_QUERY when IR methods exist. "
                        + "Returns FACT observations only (verificationStatus STATIC_INFERRED) with "
                        + "coverageStatus/stopReason when incomplete; raw secrets stay redacted; "
                        + "never executes bytecode, opens network, or upgrades verificationStatus. "
                        + "Propose DEFAULT_SECRET_HS256 only when jwtSecretMaterialFound/mintable=true; "
                        + "otherwise prefer MISSING_AUTH / EMPTY_BEARER / ALG_NONE. "
                        + "FrameworkAdapter well-known keys and secondaryAuthHeaderName are HINTS, "
                        + "not harvested FACT.",
                schema.jsonSchema(), OverflowPolicy.TRUNCATE);
        return new RegisteredTool(definition, schema, (call, context) -> {
            String kind = call.arguments().has("kind")
                    ? call.arguments().get("kind").asText("").trim() : "";
            String query = call.arguments().has("query") ? call.arguments().get("query").asText() : "";
            int limit = call.arguments().has("limit") ? call.arguments().get("limit").asInt() : 20;
            List<ToolDataSource.FactRecord> records =
                    source.queryCode(context.scope(), kind, query, limit);
            if (records == null || records.size() > Math.max(1, Math.min(50, limit))) {
                throw new IllegalStateException("invalid code_query result");
            }
            List<ToolOutput> outputs = new ArrayList<>();
            for (ToolDataSource.FactRecord record : records) {
                requireScope(context, record);
                outputs.add(new ToolOutput(OutputKind.FACT, record.reference(), record.value()));
            }
            return outputs;
        });
    }

    private RegisteredTool planPropose() {
        Map<String, Field> planFields = new LinkedHashMap<>();
        planFields.put("entrypointRef", Field.string(1024));
        planFields.put("objective", Field.string(4096));
        planFields.put("candidateInputs", Field.stringArray(16, 1024));
        planFields.put("maxCandidates", Field.integer(1, 16));
        planFields.put("track", Field.string(32));
        planFields.put("method", Field.string(16));
        planFields.put("contentType", Field.string(128));
        planFields.put("maxAttempts", Field.integer(1, 8));
        planFields.put("techniqueId", Field.string(64));
        planFields.put("rationale", Field.string(512));
        planFields.put("confidence", Field.number(0, 1));
        planFields.put("evidenceRefs", Field.stringArray(8, 256));
        planFields.put("authorizationHeader", Field.string(2048));
        planFields.put("secondaryAuthorizationHeader", Field.string(2048));
        planFields.put("bladeAuthHeader", Field.string(2048)); // deprecated wire 别名
        planFields.put("query", Field.string(256));
        planFields.put("bodyHint", Field.string(1024));
        ToolSchema schema = new ToolSchema(planFields, Set.of("entrypointRef", "objective"));
        ToolDefinition definition = new ToolDefinition("plan_propose",
                "Create a non-executing, evidence-linked candidate plan or auth-bypass PoC; "
                        + "it grants no capabilities. entrypointRef must resolve to a scan entry: prefer "
                        + "entry:<scanEntryId> (for example entry:entry-ann-1); bare scanEntryId and unambiguous "
                        + "entry:METHOD:route aliases are accepted. For AUTH_ANALYSIS, author structured PoCs with "
                        + "techniqueId plus optional authorizationHeader/secondaryAuthorizationHeader "
                        + "(deprecated alias bladeAuthHeader)/query/bodyHint "
                        + "(AI-authored JWT/header material is accepted under length/charset gates). "
                        + "Optional experiment-plan fields remain server-gated. Cannot change network/mount/command.",
                schema.jsonSchema(), OverflowPolicy.DENY);
        return new RegisteredTool(definition, schema, (call, context) -> {
            String reference = call.arguments().get("entrypointRef").asText();
            ToolDataSource.FactRecord entrypoint = requireExistingEntry(context.scope(), reference);
            requireScope(context, entrypoint);
            String canonicalRef = entrypoint.reference();
            int maximum = call.arguments().has("maxCandidates")
                    ? call.arguments().get("maxCandidates").asInt() : 8;
            ArrayNode candidates = JSON.createArrayNode();
            if (call.arguments().has("candidateInputs")) {
                int count = 0;
                for (JsonNode candidate : call.arguments().get("candidateInputs")) {
                    if (count++ >= maximum) break;
                    candidates.add(candidate.asText());
                }
            }
            ObjectNode plan = JSON.createObjectNode();
            plan.put("role", context.role().name());
            plan.put("objective", call.arguments().get("objective").asText());
            plan.put("sourceEvidenceRef", canonicalRef);
            plan.set("candidateInputs", candidates);
            // 仅当提出 entry:* 时对可选 PathRun experiment 字段做服务端闸门。
            if (call.arguments().has("track")
                    || call.arguments().has("method")
                    || call.arguments().has("contentType")
                    || call.arguments().has("maxAttempts")
                    || call.arguments().has("techniqueId")) {
                String trackName = call.arguments().has("track")
                        ? call.arguments().get("track").asText("UNAUTH") : "UNAUTH";
                IdentityTrack track;
                try {
                    track = IdentityTrack.valueOf(trackName);
                } catch (IllegalArgumentException invalid) {
                    throw new IllegalArgumentException("track is invalid");
                }
                String method = call.arguments().has("method")
                        ? call.arguments().get("method").asText("GET") : "GET";
                String contentType = call.arguments().has("contentType")
                        ? call.arguments().get("contentType").asText("application/json")
                        : "application/json";
                int maxAttempts = call.arguments().has("maxAttempts")
                        ? call.arguments().get("maxAttempts").asInt(2) : 2;
                List<String> planInputs = new ArrayList<>();
                for (int i = 0; i < candidates.size() && planInputs.size() < 8; i++) {
                    planInputs.add(candidates.get(i).asText());
                }
                ExperimentPlan experiment = new ExperimentPlan(
                        "plan:" + context.jobId() + ":" + call.callId(),
                        canonicalRef, track, method, contentType, List.of(),
                        track != IdentityTrack.UNAUTH, "2xx", "", maxAttempts,
                        planInputs, "COMPLETED", "");
                ExperimentPlanValidator.validate(experiment, 8);
                source.acceptExperimentPlan(context.scope(), experiment);
                plan.put("planId", experiment.planId());
                plan.put("track", track.name());
                plan.put("method", experiment.method());
                plan.put("contentType", experiment.contentType());
                plan.put("maxAttempts", experiment.maxAttempts());
                plan.put("serverGated", true);
                plan.put("boundForExecution", true);
            }
            String secondaryAuth = firstNonBlankArg(call.arguments(),
                    "secondaryAuthorizationHeader", "bladeAuthHeader");
            boolean authPoc = (call.arguments().has("techniqueId")
                    && !call.arguments().get("techniqueId").asText("").isBlank())
                    || (call.arguments().has("authorizationHeader")
                    && !call.arguments().get("authorizationHeader").asText("").isBlank())
                    || !secondaryAuth.isBlank();
            if (authPoc) {
                Double confidence = call.arguments().has("confidence")
                        && call.arguments().get("confidence").isNumber()
                        ? call.arguments().get("confidence").asDouble() : null;
                AuthBypassCandidate bypass = AuthBypassFeasibility.fromPlanPropose(
                        canonicalRef,
                        call.arguments().has("techniqueId")
                                ? call.arguments().get("techniqueId").asText("CUSTOM_POC") : "CUSTOM_POC",
                        plan.has("track") ? plan.get("track").asText() : null,
                        call.arguments().has("rationale")
                                ? call.arguments().get("rationale").asText("")
                                : call.arguments().get("objective").asText(""),
                        call.arguments().get("evidenceRefs"),
                        confidence,
                        call.arguments().has("authorizationHeader")
                                ? call.arguments().get("authorizationHeader").asText("") : "",
                        secondaryAuth,
                        call.arguments().has("query") ? call.arguments().get("query").asText("") : "",
                        call.arguments().has("bodyHint") ? call.arguments().get("bodyHint").asText("") : "",
                        null);
                plan.put("techniqueId", bypass.techniqueId());
                plan.put("track", bypass.track().name());
                plan.put("rationale", bypass.rationale());
                plan.put("confidence", bypass.confidence());
                plan.set("bypassPoC", AuthBypassFeasibility.toJson(bypass));
                plan.set("bypassCandidate", plan.get("bypassPoC"));
                plan.put("classification", "INFERENCE");
            }
            plan.putArray("allowedActions").add("REVIEW_FACTS").add("SELECT_CANDIDATE_INPUTS");
            plan.put("executionRequested", false);
            return List.of(new ToolOutput(OutputKind.INFERENCE,
                    "plan:" + context.jobId() + ":" + call.callId(), plan));
        });
    }

    private RegisteredTool fuzzStrategyGet() {
        ToolSchema schema = new ToolSchema(Map.of(
                "sinkId", Field.string(256),
                "sinkCategory", Field.string(64)), Set.of("sinkId"));
        ToolDefinition definition = new ToolDefinition("fuzz_strategy_get",
                "Return a server-owned, sink-category typed fuzz strategy (ProbeTemplates). "
                        + "Does not execute probes, open network, or upgrade verificationStatus. "
                        + "Use selected probe inputHints as sandbox_probe candidateInputs under server gates.",
                schema.jsonSchema(), OverflowPolicy.TRUNCATE);
        return new RegisteredTool(definition, schema, (call, context) -> {
            String sinkId = call.arguments().get("sinkId").asText();
            String requestedCategory = call.arguments().has("sinkCategory")
                    ? call.arguments().get("sinkCategory").asText("") : "";
            ToolDataSource.FactRecord matchedSink = null;
            for (ToolDataSource.FactRecord record : source.searchFacts(
                    context.scope(), "SINK", sinkId, 8)) {
                requireScope(context, record);
                boolean exactReference = ("sink:" + sinkId).equals(record.reference());
                boolean exactValue = record.value().has("id")
                        && sinkId.equals(record.value().get("id").asText(""));
                if (exactReference || exactValue) {
                    matchedSink = record;
                    break;
                }
            }
            if (matchedSink == null) {
                throw new MissingException("SINK_NOT_FOUND");
            }
            String factCategory = matchedSink.value().has("category")
                    ? matchedSink.value().get("category").asText("") : "";
            if (!requestedCategory.isBlank() && !factCategory.isBlank()
                    && !requestedCategory.equalsIgnoreCase(factCategory)) {
                throw new IllegalArgumentException("SINK_CATEGORY_MISMATCH");
            }
            String category = requestedCategory.isBlank() ? factCategory : requestedCategory;
            FuzzStrategyRegistry.FuzzStrategy strategy = FuzzStrategyRegistry.forSink(category);
            ObjectNode node = JSON.createObjectNode();
            node.put("sinkId", sinkId);
            node.put("sinkCategory", strategy.sinkCategory());
            node.put("verificationStatus", "STATIC_INFERRED");
            node.put("classification", "RULE_GENERATED");
            ArrayNode templates = node.putArray("probeTemplates");
            for (FuzzStrategyRegistry.ProbeTemplate template : strategy.probeTemplates()) {
                ObjectNode row = templates.addObject();
                row.put("name", template.name());
                row.put("inputHint", template.inputHint());
                row.put("expectedSignal", template.expectedSignal());
            }
            return List.of(new ToolOutput(OutputKind.INFERENCE,
                    "fuzz-strategy:" + sinkId, node));
        });
    }

    private RegisteredTool sandboxProbe() {
        Map<String, Field> probeFields = new LinkedHashMap<>();
        probeFields.put("entrypointRef", Field.string(1024));
        probeFields.put("candidateInputs", Field.stringArray(16, 1024));
        probeFields.put("maxRequests", Field.integer(1, 8));
        probeFields.put("techniqueId", Field.string(64));
        probeFields.put("track", Field.string(64));
        probeFields.put("objective", Field.string(1024));
        probeFields.put("expectedSignal", Field.string(512));
        probeFields.put("stopCondition", Field.string(256));
        probeFields.put("coverageGapRef", Field.string(256));
        probeFields.put("experimentPlanId", Field.string(256));
        probeFields.put("hypothesisId", Field.string(256));
        probeFields.put("planKind", Field.string(64));
        probeFields.put("authorizationHeader", Field.string(2048));
        probeFields.put("secondaryAuthorizationHeader", Field.string(2048));
        probeFields.put("bladeAuthHeader", Field.string(2048));
        ToolSchema schema = new ToolSchema(Map.copyOf(probeFields), Set.of("entrypointRef"));
        ToolDefinition definition = new ToolDefinition("sandbox_probe",
                "Request a bounded server-owned loopback probe for an existing entrypoint. "
                        + "entrypointRef must resolve to a scan entry: prefer entry:<scanEntryId> "
                        + "(for example entry:entry-ann-1); bare scanEntryId and unambiguous "
                        + "entry:METHOD:route aliases from PathRun facts are accepted; raw paths are rejected. "
                        + "PATH_EXPLORATION may probe only an explicit coverage gap: must supply track, "
                        + "objective, and coverageGapRef when gaps exist (coverageGapRef must match a "
                        + "server gap id). expectedSignal and stopCondition are server-gated labels only. "
                        + "Optional experimentPlanId is a server-gated label. "
                        + "Optional hypothesisId and planKind bind the probe to a SecurityHypothesis "
                        + "experiment (REACHABILITY/DATAFLOW_DIFF/GUARD_DIFF/STATE_SEQUENCE/"
                        + "TYPESTATE_API/CONCURRENCY_RESOURCE); they cannot elevate verification status. "
                        + "Optional authorizationHeader and secondaryAuthorizationHeader "
                        + "(deprecated wire alias: bladeAuthHeader) are independent auth channels "
                        + "(length/charset gated); omit them or pass \"\" for MISSING_AUTH / unauthenticated "
                        + "probes — never invent a fake Bearer, and never assume one channel copies to the other. "
                        + "Optional techniqueId labels the PoC or selects a server fallback synthesizer when no header "
                        + "is supplied. The model cannot choose command, image, mount, network, UID, or budget. "
                        + "Probe outcomes are facts with state/lifecycle/stopReason/failureCode; only "
                        + "COMPLETED+pathRunCount>0 counts as an effective attempt.",
                schema.jsonSchema(), OverflowPolicy.DENY);
        return new RegisteredTool(definition, schema, (call, context) -> {
            String reference = call.arguments().get("entrypointRef").asText();
            ToolDataSource.FactRecord entrypoint = requireExistingEntry(context.scope(), reference);
            requireScope(context, entrypoint);
            String canonicalRef = entrypoint.reference();
            List<String> inputs = new ArrayList<>();
            if (call.arguments().has("candidateInputs")) {
                for (JsonNode value : call.arguments().get("candidateInputs")) inputs.add(value.asText());
            }
            int maxRequests = call.arguments().has("maxRequests")
                    ? call.arguments().get("maxRequests").asInt() : 1;
            String techniqueId = call.arguments().has("techniqueId")
                    ? call.arguments().get("techniqueId").asText("").trim() : "";
            if (!techniqueId.isEmpty() && !techniqueId.matches("[A-Za-z][A-Za-z0-9_]{1,63}")) {
                throw new IllegalArgumentException("techniqueId is invalid");
            }
            String track = call.arguments().has("track")
                    ? call.arguments().get("track").asText("").trim() : "";
            String objective = call.arguments().has("objective")
                    ? call.arguments().get("objective").asText("").trim() : "";
            String coverageGapRef = call.arguments().has("coverageGapRef")
                    ? call.arguments().get("coverageGapRef").asText("").trim() : "";
            if (coverageGapRef.startsWith("gap:")) {
                coverageGapRef = coverageGapRef.substring(4);
            }
            String experimentPlanId = call.arguments().has("experimentPlanId")
                    ? call.arguments().get("experimentPlanId").asText("").trim() : "";
            String hypothesisId = call.arguments().has("hypothesisId")
                    ? call.arguments().get("hypothesisId").asText("").trim() : "";
            String planKindRaw = call.arguments().has("planKind")
                    ? call.arguments().get("planKind").asText("").trim() : "";
            ExperimentPlanKind planKind = null;
            if (!planKindRaw.isEmpty()) {
                planKind = HypothesisExperimentPlanValidator.requirePlanKind(planKindRaw);
            }
            if ((!hypothesisId.isEmpty() && planKind == null)
                    || (hypothesisId.isEmpty() && planKind != null)) {
                throw new IllegalArgumentException("HYPOTHESIS_PLAN_FIELDS_REQUIRED");
            }
            source.validateHypothesisBinding(
                    context.scope(), hypothesisId,
                    planKind == null ? "" : planKind.name(),
                    experimentPlanId, canonicalRef);
            if (context.role() == AgentRole.PATH_EXPLORATION) {
                if (track.isBlank() || objective.isBlank()) {
                    throw new IllegalArgumentException("PATH_PROBE_FIELDS_REQUIRED");
                }
                List<String> gaps = source.coverageGapIds(context.scope());
                if (!gaps.isEmpty()) {
                    if (coverageGapRef.isBlank() || !gaps.contains(coverageGapRef)) {
                        throw new IllegalArgumentException("COVERAGE_GAP_REQUIRED");
                    }
                }
            }
            if (context.role() == AgentRole.VULNERABILITY_TRIAGE
                    && (track.isBlank() || objective.isBlank())) {
                throw new IllegalArgumentException("TRIAGE_PROBE_FIELDS_REQUIRED");
            }
            String authorizationHeader = call.arguments().has("authorizationHeader")
                    ? call.arguments().get("authorizationHeader").asText("") : "";
            if (!authorizationHeader.isEmpty()) {
                // 经 candidate 构造器校验边界，不要求 technique enum。
                AuthBypassCandidate.validateAuthMaterialOnly(authorizationHeader);
            }
            String bladeAuthHeader = firstNonBlankArg(call.arguments(),
                    "secondaryAuthorizationHeader", "bladeAuthHeader");
            if (!bladeAuthHeader.isEmpty()) {
                AuthBypassCandidate.validateAuthMaterialOnly(bladeAuthHeader);
            }
            try {
                ToolDataSource.FactRecord result = source.requestSandboxProbe(
                        context.scope(), context.principalId(), context.jobId(), call.callId(),
                        canonicalRef, inputs, maxRequests,
                        techniqueId.isEmpty() ? null : techniqueId.toUpperCase(Locale.ROOT),
                        authorizationHeader.isEmpty() ? null : authorizationHeader,
                        bladeAuthHeader.isEmpty() ? null : bladeAuthHeader,
                        experimentPlanId.isEmpty() ? null : experimentPlanId)
                        .orElseThrow(() -> new MissingException("SANDBOX_PROBE_UNAVAILABLE"));
                requireScope(context, result);
                JsonNode enriched = attachHypothesisPlanFields(
                        result.value(), hypothesisId, planKind, experimentPlanId);
                return List.of(new ToolOutput(OutputKind.FACT, result.reference(), enriched));
            } catch (MissingException | IllegalArgumentException | ScopeException | SecurityException exception) {
                throw exception;
            } catch (Exception exception) {
                ObjectNode fact = probeFailureFact(canonicalRef, context.jobId(), exception);
                attachHypothesisPlanFields(fact, hypothesisId, planKind, experimentPlanId);
                return List.of(new ToolOutput(OutputKind.FACT,
                        "sandbox-probe:failed:" + context.jobId() + ":" + call.callId(), fact));
            }
        });
    }

    private static JsonNode attachHypothesisPlanFields(JsonNode value,
                                                       String hypothesisId,
                                                       ExperimentPlanKind planKind,
                                                       String experimentPlanId) {
        if (!(value instanceof ObjectNode node)) {
            return value;
        }
        if (hypothesisId != null && !hypothesisId.isBlank()) {
            node.put("hypothesisId", hypothesisId);
        }
        if (planKind != null) {
            node.put("planKind", planKind.name());
        }
        if (experimentPlanId != null && !experimentPlanId.isBlank()
                && !node.has("experimentPlanId")) {
            node.put("experimentPlanId", experimentPlanId);
        }
        return node;
    }

    private ToolDataSource.FactRecord requireExistingEntry(ToolExecutionContext.Scope scope, String reference)
            throws Exception {
        try {
            return source.resolveEntrypoint(scope, reference)
                    .orElseThrow(() -> new MissingException(EntryRefResolver.CODE_NOT_FOUND));
        } catch (IllegalArgumentException exception) {
            String code = argumentErrorCode(exception);
            if (EntryRefResolver.CODE_NOT_FOUND.equals(code)) {
                throw new MissingException(EntryRefResolver.CODE_NOT_FOUND);
            }
            throw new IllegalArgumentException(code);
        }
    }

    private static ObjectNode probeFailureFact(String canonicalRef, String jobId, Exception exception) {
        ObjectNode fact = JSON.createObjectNode();
        fact.put("schemaVersion", 1);
        fact.put("state", "FAILED");
        fact.put("lifecycle", "FAILED");
        fact.put("entrypointRef", canonicalRef == null ? "" : canonicalRef);
        fact.put("executor", "SERVER_OWNED_TRUSTED_DOCKER");
        fact.put("networkMode", "DENY");
        fact.put("retryable", false);
        String failureCode = probeFailureCode(exception);
        fact.put("failureCode", failureCode);
        fact.put("stopReason", "WORKER_FAILURE");
        if (jobId != null && !jobId.isBlank()) {
            fact.put("jobId", jobId);
        }
        String detail = exception.getMessage();
        if (detail != null && !detail.isBlank()) {
            fact.put("detail", detail.length() > 240 ? detail.substring(0, 240) : detail);
        }
        return fact;
    }

    private static String probeFailureCode(Exception exception) {
        String message = exception.getMessage();
        if (message != null) {
            String trimmed = message.trim();
            if (trimmed.matches("[A-Z][A-Z0-9_]{2,127}")) {
                return trimmed;
            }
            if (trimmed.contains("EMPTY_PROBE_EVENTS")) return "EMPTY_PROBE_EVENTS";
            if (trimmed.contains("EXTERNAL_ARTIFACT")) return "EXTERNAL_ARTIFACT_EXECUTION_FAILED";
            if (trimmed.contains("sandbox probe job limit")) return "SANDBOX_PROBE_JOB_LIMIT";
        }
        String simple = exception.getClass().getSimpleName();
        if (simple != null && !simple.isBlank() && simple.length() <= 128) {
            return "PROBE_" + simple.replaceAll("([a-z])([A-Z])", "$1_$2")
                    .toUpperCase(Locale.ROOT)
                    .replaceAll("[^A-Z0-9_]", "_");
        }
        return "TOOL_EXECUTION_FAILED";
    }

    /** 命名 JSON 参数中取首个非 blank（通用名优先于 deprecated 别名）。 */
    private static String firstNonBlankArg(JsonNode arguments, String... names) {
        if (arguments == null || names == null) return "";
        for (String name : names) {
            if (name == null || !arguments.has(name)) continue;
            String value = arguments.get(name).asText("");
            if (value != null && !value.isBlank()) return value;
        }
        return "";
    }

    private static void requireScope(ToolExecutionContext context, ToolDataSource.FactRecord record) {
        if (!context.scope().equals(record.scope())) throw new ScopeException();
    }

    private static void add(Map<String, RegisteredTool> target, RegisteredTool tool) {
        if (target.put(tool.definition().name(), tool) != null) {
            throw new IllegalStateException("duplicate tool");
        }
    }

    private static boolean exceedsJsonDepth(JsonNode root, int maximum) {
        ArrayDeque<NodeDepth> pending = new ArrayDeque<>();
        pending.push(new NodeDepth(root, 1));
        while (!pending.isEmpty()) {
            NodeDepth current = pending.pop();
            if (current.depth() > maximum) return true;
            if (current.node() != null && current.node().isContainerNode()) {
                for (JsonNode child : current.node()) {
                    pending.push(new NodeDepth(child, current.depth() + 1));
                }
            }
        }
        return false;
    }

    private record NodeDepth(JsonNode node, int depth) { }

    private static boolean containsReservedName(JsonNode node, Set<String> allowedTopLevelFields) {
        return containsReservedName(node, allowedTopLevelFields, true);
    }

    private static boolean containsReservedName(
            JsonNode node, Set<String> allowedTopLevelFields, boolean atTopLevel) {
        if (node == null) return false;
        Set<String> allowed = allowedTopLevelFields == null ? Set.of() : allowedTopLevelFields;
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.properties().iterator();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String key = field.getKey() == null ? "" : field.getKey();
                String normalized = key.replace("_", "").replace("-", "").toLowerCase(Locale.ROOT);
                boolean schemaAllowed = atTopLevel && allowed.contains(key);
                if (!schemaAllowed && RESERVED_ARGUMENT_NAMES.contains(normalized)) {
                    return true;
                }
                if (containsReservedName(field.getValue(), allowed, false)) {
                    return true;
                }
            }
        } else if (node.isArray()) {
            for (JsonNode child : node) {
                if (containsReservedName(child, allowed, false)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String argumentErrorCode(IllegalArgumentException exception) {
        String message = exception.getMessage();
        if (message == null || message.isBlank()) return "TOOL_ARGUMENT_REJECTED";
        String trimmed = message.trim();
        // control-plane / candidate 闸门抛出的稳定大写 code。
        if (trimmed.matches("[A-Z][A-Z0-9_]{2,127}")) {
            return trimmed;
        }
        return switch (trimmed) {
            case "track is invalid" -> "EXPERIMENT_TRACK_INVALID";
            case "method is not allowlisted" -> "EXPERIMENT_METHOD_NOT_ALLOWED";
            case "contentType is not allowlisted" -> "EXPERIMENT_CONTENT_TYPE_NOT_ALLOWED";
            case "destructive payload rejected" -> "EXPERIMENT_DESTRUCTIVE_PAYLOAD_REJECTED";
            case "techniqueId is invalid" -> "TECHNIQUE_ID_INVALID";
            case "authorization material exceeds bound" -> "AUTHORIZATION_HEADER_BOUND_EXCEEDED";
            case "authorization material charset rejected" -> "AUTHORIZATION_HEADER_CHARSET_REJECTED";
            case "sandbox probe requires an entry evidence reference" -> EntryRefResolver.CODE_MUST_BE_ENTRY;
            case "sandbox probe entry is not in scan" -> EntryRefResolver.CODE_NOT_FOUND;
            case "sandbox probe entry is not an eligible HTTP endpoint" -> "SANDBOX_PROBE_ENTRY_NOT_HTTP";
            default -> "TOOL_ARGUMENT_REJECTED";
        };
    }

    public record ToolDefinition(String name, String description, JsonNode inputSchema,
                                 OverflowPolicy overflowPolicy) {
        public ToolDefinition {
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(description, "description");
            Objects.requireNonNull(inputSchema, "inputSchema");
            Objects.requireNonNull(overflowPolicy, "overflowPolicy");
        }
    }

    public enum OverflowPolicy { TRUNCATE, DENY }

    private record RegisteredTool(ToolDefinition definition, ToolSchema schema, Handler handler) { }

    @FunctionalInterface
    private interface Handler {
        List<ToolOutput> execute(ToolCall call, ToolExecutionContext context) throws Exception;
    }

    private record ToolSchema(Map<String, Field> fields, Set<String> required) {
        ToolSchema {
            fields = Map.copyOf(fields);
            required = Set.copyOf(required);
            if (!fields.keySet().containsAll(required)) throw new IllegalArgumentException("unknown required field");
        }

        String validate(JsonNode arguments) {
            if (!arguments.isObject()) return "ARGUMENTS_MUST_BE_OBJECT";
            for (Map.Entry<String, JsonNode> argument : arguments.properties()) {
                String name = argument.getKey();
                Field field = fields.get(name);
                if (field == null) return "UNKNOWN_ARGUMENT";
                if (!field.valid(argument.getValue())) return "ARGUMENT_SCHEMA_MISMATCH";
            }
            for (String name : required) {
                if (!arguments.has(name)) return "MISSING_ARGUMENT";
                // 必填字符串须非 blank；可选字符串可为 ""（如 MISSING_AUTH）。
                Field field = fields.get(name);
                if (field != null && field.kind() == Kind.STRING
                        && arguments.get(name).isTextual()
                        && arguments.get(name).asText().isBlank()) {
                    return "MISSING_ARGUMENT";
                }
            }
            return null;
        }

        JsonNode jsonSchema() {
            ObjectNode schema = JSON.createObjectNode();
            schema.put("type", "object");
            schema.put("additionalProperties", false);
            ObjectNode properties = schema.putObject("properties");
            fields.forEach((name, field) -> properties.set(name, field.schema()));
            ArrayNode requiredNode = schema.putArray("required");
            required.stream().sorted().forEach(requiredNode::add);
            return schema;
        }
    }

    private record Field(Kind kind, int maximum, int minimum) {
        static Field string(int maximum) { return new Field(Kind.STRING, maximum, 0); }
        static Field integer(int minimum, int maximum) { return new Field(Kind.INTEGER, maximum, minimum); }
        static Field number(int minimum, int maximum) { return new Field(Kind.NUMBER, maximum, minimum); }
        static Field stringArray(int maximumItems, int maximumLength) {
            return new Field(Kind.STRING_ARRAY, maximumItems, maximumLength);
        }

        boolean valid(JsonNode node) {
            return switch (kind) {
                // 可选字符串可为 blank（MISSING_AUTH authorizationHeader:""）；
                // 必填非 blank 在 ToolSchema.validate 中强制。
                case STRING -> node.isTextual()
                        && node.asText().length() <= maximum && node.asText().indexOf('\0') < 0;
                case INTEGER -> node.isIntegralNumber() && node.canConvertToInt()
                        && node.asInt() >= minimum && node.asInt() <= maximum;
                case NUMBER -> node.isNumber() && node.asDouble() >= minimum && node.asDouble() <= maximum;
                case STRING_ARRAY -> {
                    if (!node.isArray() || node.size() > maximum) yield false;
                    boolean valid = true;
                    for (JsonNode child : node) {
                        if (!child.isTextual() || child.asText().length() > minimum
                                || child.asText().indexOf('\0') >= 0) valid = false;
                    }
                    yield valid;
                }
            };
        }

        JsonNode schema() {
            ObjectNode node = JSON.createObjectNode();
            switch (kind) {
                case STRING -> {
                    node.put("type", "string");
                    node.put("maxLength", maximum);
                }
                case INTEGER -> {
                    node.put("type", "integer");
                    node.put("minimum", minimum);
                    node.put("maximum", maximum);
                }
                case NUMBER -> {
                    node.put("type", "number");
                    node.put("minimum", minimum);
                    node.put("maximum", maximum);
                }
                case STRING_ARRAY -> {
                    node.put("type", "array");
                    node.put("maxItems", maximum);
                    node.putObject("items").put("type", "string").put("maxLength", minimum);
                }
            }
            return node;
        }
    }

    private enum Kind { STRING, INTEGER, NUMBER, STRING_ARRAY }

    private static final class MissingException extends RuntimeException {
        private final String code;
        private MissingException(String code) { this.code = code; }
    }

    private static final class ScopeException extends RuntimeException { }
}

package com.aq.jvmsentinel.ai.tool;

import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.OutputKind;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolCall;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolOutput;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolResult;
import com.aq.jvmsentinel.ai.tool.CanonicalToolContracts.ToolStatus;
import com.aq.jvmsentinel.provider.AgentRole;
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
 * Code-owned registry and fail-closed dispatcher. Provider adapters may expose
 * {@link #definitionsFor(AgentRole)}, but cannot register handlers or alter role grants.
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
        add(fixed, planPropose());
        add(fixed, sandboxProbe());
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
        if (containsReservedName(call.arguments())) {
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

    private RegisteredTool factsSearch() {
        ToolSchema schema = new ToolSchema(
                Map.of("kind", Field.string(64), "query", Field.string(1024), "limit", Field.integer(1, 100)),
                Set.of("kind"));
        ToolDefinition definition = new ToolDefinition("facts_search",
                "Search already-indexed, read-only facts in the server-bound project.",
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

    private RegisteredTool planPropose() {
        ToolSchema schema = new ToolSchema(Map.of(
                "entrypointRef", Field.string(1024),
                "objective", Field.string(4096),
                "candidateInputs", Field.stringArray(16, 1024),
                "maxCandidates", Field.integer(1, 16)), Set.of("entrypointRef", "objective"));
        ToolDefinition definition = new ToolDefinition("plan_propose",
                "Create a non-executing, evidence-linked candidate plan; it grants no capabilities.",
                schema.jsonSchema(), OverflowPolicy.DENY);
        return new RegisteredTool(definition, schema, (call, context) -> {
            String reference = call.arguments().get("entrypointRef").asText();
            ToolDataSource.FactRecord entrypoint = source.findEvidence(context.scope(), reference)
                    .orElseThrow(() -> new MissingException("ENTRYPOINT_NOT_FOUND"));
            requireScope(context, entrypoint);
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
            plan.put("sourceEvidenceRef", reference);
            plan.set("candidateInputs", candidates);
            plan.putArray("allowedActions").add("REVIEW_FACTS").add("SELECT_CANDIDATE_INPUTS");
            plan.put("executionRequested", false);
            return List.of(new ToolOutput(OutputKind.INFERENCE,
                    "plan:" + context.jobId() + ":" + call.callId(), plan));
        });
    }

    private RegisteredTool sandboxProbe() {
        ToolSchema schema = new ToolSchema(Map.of(
                "entrypointRef", Field.string(1024),
                "candidateInputs", Field.stringArray(16, 1024),
                "maxRequests", Field.integer(1, 8)), Set.of("entrypointRef"));
        ToolDefinition definition = new ToolDefinition("sandbox_probe",
                "Request a bounded server-owned loopback probe for an existing entrypoint. "
                        + "The model cannot choose the command, route, network, mount, or budget.",
                schema.jsonSchema(), OverflowPolicy.DENY);
        return new RegisteredTool(definition, schema, (call, context) -> {
            String reference = call.arguments().get("entrypointRef").asText();
            List<String> inputs = new ArrayList<>();
            if (call.arguments().has("candidateInputs")) {
                for (JsonNode value : call.arguments().get("candidateInputs")) inputs.add(value.asText());
            }
            int maxRequests = call.arguments().has("maxRequests")
                    ? call.arguments().get("maxRequests").asInt() : 1;
            ToolDataSource.FactRecord result = source.requestSandboxProbe(
                    context.scope(), context.principalId(), context.jobId(), reference, inputs, maxRequests)
                    .orElseThrow(() -> new MissingException("SANDBOX_PROBE_UNAVAILABLE"));
            requireScope(context, result);
            return List.of(new ToolOutput(OutputKind.FACT, result.reference(), result.value()));
        });
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

    private static boolean containsReservedName(JsonNode node) {
        if (node == null) return false;
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.properties().iterator();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String normalized = field.getKey().replace("_", "").replace("-", "")
                        .toLowerCase(Locale.ROOT);
                if (RESERVED_ARGUMENT_NAMES.contains(normalized) || containsReservedName(field.getValue())) {
                    return true;
                }
            }
        } else if (node.isArray()) {
            for (JsonNode child : node) if (containsReservedName(child)) return true;
        }
        return false;
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
            for (String name : required) if (!arguments.has(name)) return "MISSING_ARGUMENT";
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
        static Field stringArray(int maximumItems, int maximumLength) {
            return new Field(Kind.STRING_ARRAY, maximumItems, maximumLength);
        }

        boolean valid(JsonNode node) {
            return switch (kind) {
                case STRING -> node.isTextual() && !node.asText().isBlank()
                        && node.asText().length() <= maximum && node.asText().indexOf('\0') < 0;
                case INTEGER -> node.isIntegralNumber() && node.canConvertToInt()
                        && node.asInt() >= minimum && node.asInt() <= maximum;
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
                case STRING_ARRAY -> {
                    node.put("type", "array");
                    node.put("maxItems", maximum);
                    node.putObject("items").put("type", "string").put("maxLength", minimum);
                }
            }
            return node;
        }
    }

    private enum Kind { STRING, INTEGER, STRING_ARRAY }

    private static final class MissingException extends RuntimeException {
        private final String code;
        private MissingException(String code) { this.code = code; }
    }

    private static final class ScopeException extends RuntimeException { }
}

package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.experiment.ExperimentPlanKind;
import com.aq.jvmsentinel.domain.experiment.ExperimentSignal;
import com.aq.jvmsentinel.domain.experiment.HypothesisExperimentPlan;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * P0-18：将 entry × 0-n parameter space 编译为服务端 owned experiment plan。
 * 空 query/body 为合法 shape，须携带 empty-input rationale。
 */
public final class EntryParameterExperimentCompiler {
    public static final String PRODUCER = "entry-parameter-experiment-compiler/0.1";

    private EntryParameterExperimentCompiler() {
    }

    public record CompiledParameter(
            String name,
            String location,
            String provenance,
            String sampleValue,
            boolean emptyLegal,
            String emptyInputRationale
    ) {
        public CompiledParameter {
            name = name == null ? "" : name;
            location = location == null ? "QUERY" : location;
            provenance = provenance == null ? "ENTRY_SIGNATURE" : provenance;
            sampleValue = sampleValue == null ? "" : sampleValue;
            emptyInputRationale = emptyInputRationale == null ? "" : emptyInputRationale;
        }
    }

    public record CompiledExperiment(
            String experimentPlanId,
            String entryId,
            String method,
            String route,
            IdentityTrack track,
            ExperimentPlanKind kind,
            List<CompiledParameter> parameters,
            String query,
            String body,
            String emptyInputRationale,
            List<ExperimentSignal> expectedSignals,
            List<ExperimentSignal> counterSignals,
            String readiness,
            String hypothesisId
    ) {
        public CompiledExperiment {
            Objects.requireNonNull(experimentPlanId, "experimentPlanId");
            parameters = List.copyOf(parameters == null ? List.of() : parameters);
            expectedSignals = List.copyOf(expectedSignals == null ? List.of() : expectedSignals);
            counterSignals = List.copyOf(counterSignals == null ? List.of() : counterSignals);
            query = query == null ? "" : query;
            body = body == null ? "" : body;
            emptyInputRationale = emptyInputRationale == null ? "" : emptyInputRationale;
            readiness = readiness == null ? "EXECUTABLE" : readiness;
            hypothesisId = hypothesisId == null ? "" : hypothesisId;
        }

        public Map<String, Object> toWireMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("experimentPlanId", experimentPlanId);
            map.put("entryId", entryId);
            map.put("method", method);
            map.put("route", route);
            map.put("track", track == null ? IdentityTrack.UNAUTH.name() : track.name());
            map.put("kind", kind == null ? ExperimentPlanKind.REACHABILITY.name() : kind.name());
            map.put("query", query);
            map.put("body", body);
            map.put("emptyInputRationale", emptyInputRationale);
            map.put("readiness", readiness);
            map.put("hypothesisId", hypothesisId);
            map.put("producer", PRODUCER);
            List<Map<String, Object>> params = new ArrayList<>();
            for (CompiledParameter parameter : parameters) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", parameter.name());
                row.put("location", parameter.location());
                row.put("provenance", parameter.provenance());
                row.put("sampleValue", parameter.sampleValue());
                row.put("emptyLegal", parameter.emptyLegal());
                row.put("emptyInputRationale", parameter.emptyInputRationale());
                params.add(row);
            }
            map.put("parameters", params);
            map.put("expectedSignals", expectedSignals.stream().map(ExperimentSignal::code).toList());
            map.put("counterSignals", counterSignals.stream().map(ExperimentSignal::code).toList());
            return map;
        }
    }

    /**
     * 统一 entry signature、hypothesis family、DynamicProbe ExperimentPlan 与 AUTH PoC
     * entry hint 为服务端 owned compiled experiment（P0-18）。
     */
    public static List<CompiledExperiment> compileUnified(
            List<ApiDtos.EntryDto> entries,
            List<SecurityHypothesis> hypotheses,
            List<ExperimentPlan> dynamicPlans,
            List<String> authPocEntryRefs,
            int maxPlans) {
        List<CompiledExperiment> out = new ArrayList<>(compile(entries, hypotheses, maxPlans));
        int limit = Math.max(1, Math.min(maxPlans <= 0 ? 64 : maxPlans, 256));
        if (dynamicPlans != null) {
            for (ExperimentPlan plan : dynamicPlans) {
                if (out.size() >= limit || plan == null) continue;
                out.add(fromDynamicPlan(plan));
            }
        }
        if (authPocEntryRefs != null && entries != null) {
            for (String ref : authPocEntryRefs) {
                if (out.size() >= limit || ref == null || ref.isBlank()) continue;
                for (ApiDtos.EntryDto entry : entries) {
                    if (entry == null) continue;
                    if (ref.contains(entry.id()) || ref.contains(entry.route())) {
                        CompiledExperiment compiled = compileOne(
                                entry,
                                entry.method() == null || entry.method().isBlank()
                                        ? "GET" : entry.method().toUpperCase(Locale.ROOT),
                                null,
                                ExperimentPlanKind.GUARD_DIFF);
                        out.add(new CompiledExperiment(
                                "plan:auth-poc:" + entry.id(),
                                compiled.entryId(),
                                compiled.method(),
                                compiled.route(),
                                IdentityTrack.ADMIN,
                                ExperimentPlanKind.GUARD_DIFF,
                                compiled.parameters(),
                                compiled.query(),
                                compiled.body(),
                                compiled.emptyInputRationale(),
                                expectedFor(ExperimentPlanKind.GUARD_DIFF),
                                counterFor(ExperimentPlanKind.GUARD_DIFF),
                                "MISSING_IDENTITY".equals(compiled.readiness())
                                        ? "MISSING_IDENTITY" : "EXECUTABLE",
                                compiled.hypothesisId()));
                        break;
                    }
                }
            }
        }
        return List.copyOf(out.stream().limit(limit).toList());
    }

    public static ExternalArtifactTaskExecutor.ProbeTarget toProbeTarget(CompiledExperiment compiled) {
        Objects.requireNonNull(compiled, "compiled");
        return new ExternalArtifactTaskExecutor.ProbeTarget(
                compiled.method(),
                compiled.route(),
                compiled.query(),
                compiled.track() == null ? "UNAUTH" : compiled.track().name(),
                "",
                "",
                compiled.experimentPlanId());
    }

    public static CompiledExperiment fromDynamicPlan(ExperimentPlan plan) {
        Objects.requireNonNull(plan, "plan");
        String method = plan.method() == null || plan.method().isBlank()
                ? "GET" : plan.method().toUpperCase(Locale.ROOT);
        String route = plan.entrypointRef() == null ? "/" : plan.entrypointRef().trim();
        if (route.contains(" ")) {
            String[] parts = route.split("\\s+", 2);
            if (parts.length == 2 && parts[0].matches("[A-Z]+")) {
                method = parts[0];
                route = parts[1];
            }
        }
        if (!route.startsWith("/")) route = "/" + route;
        List<CompiledParameter> parameters = new ArrayList<>();
        if (plan.requiredParameters() == null || plan.requiredParameters().isEmpty()) {
            parameters.add(new CompiledParameter(
                    "", "QUERY", "EMPTY_INPUT", "", true,
                    "DynamicProbe plan accepts empty query/body; observe downstream effects."));
        } else {
            for (String name : plan.requiredParameters()) {
                if (name == null || name.isBlank()) continue;
                parameters.add(new CompiledParameter(
                        name, "QUERY", "DYNAMIC_PROBE", "", true,
                        "Empty value remains legal for DynamicProbe parameter '" + name + "'."));
            }
        }
        String emptyRationale = parameters.stream().allMatch(p -> p.sampleValue().isBlank())
                ? "Provider DynamicProbe empty-input shape; do not flood arbitrary payloads."
                : "";
        return new CompiledExperiment(
                plan.planId() == null || plan.planId().isBlank()
                        ? "plan:dynamic:" + method + ":" + route
                        : plan.planId(),
                "entry:" + method + ":" + route,
                method,
                route,
                plan.track() == null ? IdentityTrack.UNAUTH : plan.track(),
                ExperimentPlanKind.REACHABILITY,
                parameters,
                "",
                "",
                emptyRationale,
                expectedFor(ExperimentPlanKind.REACHABILITY),
                counterFor(ExperimentPlanKind.REACHABILITY),
                plan.authRequired() ? "MISSING_IDENTITY" : "EXECUTABLE",
                ""
        );
    }

    public static List<CompiledExperiment> compile(
            List<ApiDtos.EntryDto> entries,
            List<SecurityHypothesis> hypotheses,
            int maxPlans) {
        int limit = Math.max(1, Math.min(maxPlans <= 0 ? 64 : maxPlans, 256));
        List<ApiDtos.EntryDto> entryList = entries == null ? List.of() : entries;
        List<SecurityHypothesis> hypList = hypotheses == null ? List.of() : hypotheses;
        List<CompiledExperiment> out = new ArrayList<>();
        for (ApiDtos.EntryDto entry : entryList) {
            if (entry == null || entry.route() == null || entry.route().isBlank()) continue;
            String method = entry.method() == null || entry.method().isBlank()
                    ? "GET" : entry.method().toUpperCase(Locale.ROOT);
            SecurityHypothesis matched = matchHypothesis(entry, hypList);
            HypothesisFamily family = matched == null ? HypothesisFamily.UNKNOWN : matched.family();
            for (ExperimentPlanKind kind : kindsFor(family)) {
                if (out.size() >= limit) {
                    return List.copyOf(out);
                }
                out.add(compileOne(entry, method, matched, kind));
            }
        }
        return List.copyOf(out);
    }

    public static HypothesisExperimentPlan toHypothesisPlan(CompiledExperiment compiled, String scanId) {
        Objects.requireNonNull(compiled, "compiled");
        String safeScan = scanId == null || scanId.isBlank() ? "scan-unknown" : scanId;
        String hypothesisId = compiled.hypothesisId().isBlank()
                ? "hyp:entry:" + compiled.entryId()
                : compiled.hypothesisId();
        return new HypothesisExperimentPlan(
                HypothesisExperimentPlan.SCHEMA_VERSION,
                compiled.experimentPlanId(),
                hypothesisId,
                safeScan,
                compiled.kind(),
                compiled.method() + " " + compiled.route(),
                compiled.track(),
                compiled.expectedSignals(),
                compiled.counterSignals(),
                "COMPLETED",
                2,
                "",
                ""
        );
    }

    private static CompiledExperiment compileOne(ApiDtos.EntryDto entry, String method,
                                                 SecurityHypothesis matched,
                                                 ExperimentPlanKind kind) {
        List<CompiledParameter> parameters = inferParameters(entry, method);
        boolean emptyShape = parameters.stream().allMatch(p -> p.sampleValue().isBlank());
        String emptyRationale = emptyShape
                ? "Entry accepts 0 parameters / empty query/body as a legal shape; "
                + "observe downstream Entry/Guard/Effect/State/Dependency rather than HTTP status alone."
                : "";
        String readiness = "EXECUTABLE";
        for (String precondition : entry.preconditions()) {
            if (precondition != null && precondition.toUpperCase(Locale.ROOT).contains("AUTH")) {
                readiness = "MISSING_IDENTITY";
                break;
            }
        }
        String hypothesisId = matched == null ? "" : matched.hypothesisId();
        String planId = "plan:entry:" + entry.id() + ":" + kind.name().toLowerCase(Locale.ROOT);
        return new CompiledExperiment(
                planId,
                entry.id(),
                method,
                entry.route(),
                IdentityTrack.UNAUTH,
                kind,
                parameters,
                buildQuery(parameters),
                "",
                emptyRationale,
                expectedFor(kind),
                counterFor(kind),
                readiness,
                hypothesisId
        );
    }

    private static List<CompiledParameter> inferParameters(ApiDtos.EntryDto entry, String method) {
        List<CompiledParameter> parameters = new ArrayList<>();
        List<String> declared = entry.parameters();
        String route = entry.route() == null ? "" : entry.route();
        if (declared == null || declared.isEmpty()) {
            parameters.add(new CompiledParameter(
                    "",
                    "QUERY",
                    "EMPTY_INPUT",
                    "",
                    true,
                    "Empty query is legal for " + method + " " + route
                            + "; record empty-input rationale and observe downstream effects."));
        } else {
            for (String raw : declared) {
                if (raw == null || raw.isBlank()) continue;
                String name = ProbeParameterHeuristics.resolveName(raw);
                if (name.isBlank()) continue;
                String declaredSample = ProbeParameterHeuristics.declaredSample(raw);
                String sample = !declaredSample.isBlank()
                        ? declaredSample
                        : ProbeParameterHeuristics.sampleValueFor(name, route);
                String provenance = !declaredSample.isBlank()
                        ? "ENTRY_SIGNATURE"
                        : (ProbeParameterHeuristics.looksExpression(
                                name.toLowerCase(Locale.ROOT), route.toLowerCase(Locale.ROOT))
                                ? "EXPRESSION_HEURISTIC"
                                : "ENTRY_SIGNATURE");
                parameters.add(new CompiledParameter(
                        name,
                        "QUERY",
                        provenance,
                        sample,
                        true,
                        "Empty value for parameter '" + name + "' remains a legal exploration input."));
            }
        }
        if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
            parameters.add(new CompiledParameter(
                    "body",
                    "BODY",
                    "EMPTY_INPUT",
                    "",
                    true,
                    "Empty body is a legal input shape for " + method
                            + "; do not treat missing body as probe failure by itself."));
        }
        return parameters;
    }

    private static String buildQuery(List<CompiledParameter> parameters) {
        StringBuilder sb = new StringBuilder();
        for (CompiledParameter parameter : parameters) {
            if (!"QUERY".equalsIgnoreCase(parameter.location())) continue;
            if (parameter.name().isBlank() || parameter.sampleValue().isBlank()) continue;
            if (!sb.isEmpty()) sb.append('&');
            sb.append(parameter.name()).append('=').append(parameter.sampleValue());
        }
        return sb.toString();
    }

    private static SecurityHypothesis matchHypothesis(ApiDtos.EntryDto entry,
                                                      List<SecurityHypothesis> hypotheses) {
        for (SecurityHypothesis hypothesis : hypotheses) {
            if (hypothesis == null) continue;
            String haystack = (hypothesis.source() + " " + hypothesis.effect() + " "
                    + hypothesis.hypothesisId()).toLowerCase(Locale.ROOT);
            if (haystack.contains(entry.id().toLowerCase(Locale.ROOT))
                    || haystack.contains(entry.route().toLowerCase(Locale.ROOT))) {
                return hypothesis;
            }
        }
        return null;
    }

    private static List<ExperimentPlanKind> kindsFor(HypothesisFamily family) {
        return switch (family) {
            case DATAFLOW -> List.of(ExperimentPlanKind.REACHABILITY, ExperimentPlanKind.DATAFLOW_DIFF);
            case GUARD_COVERAGE -> List.of(ExperimentPlanKind.GUARD_DIFF);
            case STATE -> List.of(ExperimentPlanKind.STATE_SEQUENCE);
            case TYPESTATE -> List.of(ExperimentPlanKind.TYPESTATE_API);
            default -> List.of(ExperimentPlanKind.REACHABILITY);
        };
    }

    private static List<ExperimentSignal> expectedFor(ExperimentPlanKind kind) {
        return switch (kind) {
            case REACHABILITY -> List.of(
                    ExperimentSignal.of("ENTRY_HIT"),
                    ExperimentSignal.of("EFFECT_HIT"));
            case DATAFLOW_DIFF -> List.of(
                    ExperimentSignal.of("EFFECT_STRUCTURE_DIFF"),
                    ExperimentSignal.of("MALICIOUS_FRAGMENT"));
            case GUARD_DIFF -> List.of(
                    ExperimentSignal.of("GUARD_BYPASS"),
                    ExperimentSignal.of("SAME_EFFECT_DIFF_IDENTITY"));
            case STATE_SEQUENCE -> List.of(
                    ExperimentSignal.of("STATE_TRANSITION"),
                    ExperimentSignal.of("INVARIANT_BROKEN"));
            case TYPESTATE_API -> List.of(
                    ExperimentSignal.of("TYPESTATE_MISUSE"),
                    ExperimentSignal.of("UNSAFE_API_SEQUENCE"));
            case CONCURRENCY_RESOURCE -> List.of(
                    ExperimentSignal.of("RACE_WINDOW"),
                    ExperimentSignal.of("TOCTOU_HIT"));
        };
    }

    private static List<ExperimentSignal> counterFor(ExperimentPlanKind kind) {
        return switch (kind) {
            case REACHABILITY -> List.of(
                    ExperimentSignal.of("AUTH_CHALLENGE"),
                    ExperimentSignal.of("UNREACHED"));
            case DATAFLOW_DIFF -> List.of(
                    ExperimentSignal.of("PARAMETERIZED_BLOCK"),
                    ExperimentSignal.of("SANITIZER_HIT"));
            case GUARD_DIFF -> List.of(
                    ExperimentSignal.of("GUARD_DENY"),
                    ExperimentSignal.of("IDENTITY_UNAVAILABLE"));
            case STATE_SEQUENCE -> List.of(
                    ExperimentSignal.of("INVARIANT_HELD"),
                    ExperimentSignal.of("SEQUENCE_REJECTED"));
            case TYPESTATE_API -> List.of(
                    ExperimentSignal.of("SAFE_REJECT"),
                    ExperimentSignal.of("PROTOCOL_OK"));
            case CONCURRENCY_RESOURCE -> List.of(
                    ExperimentSignal.of("LOCK_SERIALIZED"),
                    ExperimentSignal.of("NO_RACE"));
        };
    }

    /** Seed helper for tests that need a non-DATAFLOW hypothesis without full detector output. */
    static SecurityHypothesis seedHypothesis(String hypothesisId, String scanId, HypothesisFamily family) {
        return new SecurityHypothesis(
                SecurityHypothesis.SCHEMA_VERSION,
                hypothesisId,
                scanId,
                "security.property." + family.name().toLowerCase(Locale.ROOT),
                family,
                HypothesisLifecycle.CANDIDATE,
                PRODUCER,
                List.of(),
                List.of(),
                List.of(),
                "",
                ""
        );
    }
}

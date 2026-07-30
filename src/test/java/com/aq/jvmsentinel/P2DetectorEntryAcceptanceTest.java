package com.aq.jvmsentinel;

import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.analysis.detector.ConcurrencyResourceDetector;
import com.aq.jvmsentinel.analysis.detector.DetectorContext;
import com.aq.jvmsentinel.analysis.detector.DetectorIds;
import com.aq.jvmsentinel.analysis.detector.DetectorRecallGate;
import com.aq.jvmsentinel.analysis.detector.DetectorRegistry;
import com.aq.jvmsentinel.analysis.detector.StateSequenceDetector;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.aq.jvmsentinel.analysis.spi.ProviderBundle;
import com.aq.jvmsentinel.analysis.spi.ProviderContext;
import com.aq.jvmsentinel.analysis.spi.ProviderRegistry;
import com.aq.jvmsentinel.analysis.spi.defaults.DefaultJvmProviders;
import com.aq.jvmsentinel.analysis.spi.entry.MessageListenerEntryProvider;
import com.aq.jvmsentinel.analysis.spi.entry.ScheduledEntryProvider;
import com.aq.jvmsentinel.analysis.spi.entry.ServletFilterEntryProvider;
import com.aq.jvmsentinel.analysis.spi.entry.WebFluxEntryProvider;
import com.aq.jvmsentinel.analysis.spi.entry.WebSocketRpcEntryProvider;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.universe.ArtifactUniverse;
import com.aq.jvmsentinel.model.BytecodeFactIndex;
import com.aq.jvmsentinel.model.DependencyMap;
import com.aq.jvmsentinel.model.EntryCatalog;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.model.PathOutcomeClass;
import com.aq.jvmsentinel.model.PathRun;
import com.aq.jvmsentinel.model.PermissionMatrix;
import com.aq.jvmsentinel.model.SinkCatalog;
import com.aq.jvmsentinel.model.SqlEvent;
import com.aq.jvmsentinel.model.VerificationStatus;
import com.aq.jvmsentinel.worker.DynamicConfirmedGate;

import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 说明：P2：STATE/CONCURRENCY detector + mutation/holdout DetectorRecallGate
 * (declared AUDITED heuristic depth), family DYNAMIC_CONFIRMED fail-closed gate,
 * 与 Servlet/WebFlux/Listener/Scheduled/WebSocket EntryProvider scaffolding。
 */
public final class P2DetectorEntryAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final ObjectMapper JSON = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        try {
            ProviderRegistry.resetForTests();
            verifyBaselinesPresent();
            verifyStateSequenceDetector();
            verifyConcurrencyDetector();
            verifyMutationHoldoutRecallGates();
            verifyFamilyDynamicConfirmedGate();
            verifyEntryProvidersRegisterAndUnload();
            System.out.println("P2DetectorEntryAcceptanceTest: PASS ("
                    + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
        } finally {
            ProviderRegistry.resetForTests();
        }
    }

    private static void verifyBaselinesPresent() throws Exception {
        for (String name : List.of(
                "baselines/p2-state-concurrency.json",
                "baselines/p2-mutation-state-concurrency.json",
                "baselines/p2-holdout-state-concurrency.json")) {
            try (InputStream in = P2DetectorEntryAcceptanceTest.class.getClassLoader()
                    .getResourceAsStream(name)) {
                check(in != null, name + " present");
                JsonNode node = JSON.readTree(in);
                check(node.path("honesty").path("aiNotInBaseJudgment").asBoolean(false),
                        name + " forbids AI in base judgment");
                check(!node.path("metrics").path("stub").asBoolean(true)
                                || "unit".equals(node.path("kind").asText()),
                        name + " metrics not stub (or unit baseline)");
            }
        }
    }

    private static void verifyMutationHoldoutRecallGates() {
        DetectorRegistry full = DetectorRegistry.defaults();
        DetectorContext mutationCtx = mutationContext();
        DetectorContext holdoutCtx = holdoutContext();

        Set<String> mutationExpected = Set.of(
                StateSequenceDetector.PROP_STATE_TRANSITION_GAP,
                StateSequenceDetector.PROP_REPEAT_SUBMIT,
                ConcurrencyResourceDetector.PROP_TOCTOU);
        DetectorRecallGate.Result mutationPass =
                DetectorRecallGate.evaluate(full, mutationCtx, mutationExpected);
        check(mutationPass.passed(), "P2 mutation recall gate passes with full registry");

        Set<String> holdoutExpected = Set.of(
                StateSequenceDetector.PROP_QUOTA_INVARIANT,
                ConcurrencyResourceDetector.PROP_RACE_WINDOW,
                ConcurrencyResourceDetector.PROP_LOCK_GAP);
        DetectorRecallGate.Result holdoutPass =
                DetectorRecallGate.evaluate(full, holdoutCtx, holdoutExpected);
        check(holdoutPass.passed(), "P2 holdout recall gate passes with full registry");

        assertRemoveFails(full, mutationCtx, DetectorIds.STATE_SEQUENCE,
                Set.of(StateSequenceDetector.PROP_STATE_TRANSITION_GAP), "mutation/state");
        assertRemoveFails(full, mutationCtx, DetectorIds.CONCURRENCY_RESOURCE,
                Set.of(ConcurrencyResourceDetector.PROP_TOCTOU), "mutation/concurrency");
        assertRemoveFails(full, holdoutCtx, DetectorIds.STATE_SEQUENCE,
                Set.of(StateSequenceDetector.PROP_QUOTA_INVARIANT), "holdout/state");
        assertRemoveFails(full, holdoutCtx, DetectorIds.CONCURRENCY_RESOURCE,
                Set.of(ConcurrencyResourceDetector.PROP_RACE_WINDOW), "holdout/concurrency");
    }

    private static void assertRemoveFails(DetectorRegistry full,
                                          DetectorContext context,
                                          String detectorId,
                                          Set<String> expected,
                                          String label) {
        DetectorRegistry stripped = DetectorRecallGate.without(full, detectorId);
        check(stripped.detectors().stream().noneMatch(d -> detectorId.equals(d.id())),
                label + ": detector removed from registry");
        DetectorRecallGate.Result failed = DetectorRecallGate.evaluate(stripped, context, expected);
        check(!failed.passed(), label + ": recall gate fails after detector removal");
        check(!failed.missingProperties().isEmpty(), label + ": missing properties reported");
    }

    private static DetectorContext mutationContext() {
        ApiDtos.EntryDto stated = entry("m-state", "com.example.OrderApi", "POST", "/order/draft",
                List.of(), List.of("state=DRAFT"));
        ApiDtos.EntryDto submit = entry("m-submit", "com.example.OrderApi", "POST", "/order/submit",
                List.of(), List.of());
        BytecodeFactIndex.InstructionEvidence ev = new BytecodeFactIndex.InstructionEvidence(
                "com/example/SharedStore", "update", "()V", 0, 0);
        List<BytecodeFactIndex.CallEdge> edges = List.of(
                edge("com/example/SharedStore", "update", "java/io/File", "exists", ev),
                edge("com/example/SharedStore", "update", "java/io/File", "delete", ev)
        );
        return ctx(List.of(stated, submit), edges);
    }

    private static DetectorContext holdoutContext() {
        ApiDtos.EntryDto quota = entry("h-quota", "com.example.WalletApi", "POST", "/wallet/credit",
                List.of(), List.of());
        BytecodeFactIndex.InstructionEvidence ev = new BytecodeFactIndex.InstructionEvidence(
                "com/example/SharedStore", "update", "()V", 0, 0);
        List<BytecodeFactIndex.CallEdge> edges = List.of(
                edge("com/example/SharedStore", "update", "java/lang/Thread", "start", ev),
                edge("com/example/SharedStore", "update", "java/util/HashMap", "put", ev)
        );
        return ctx(List.of(quota), edges);
    }

    private static void verifyStateSequenceDetector() {
        check(DetectorRegistry.defaults().detectors().stream()
                        .anyMatch(d -> DetectorIds.STATE_SEQUENCE.equals(d.id())),
                "registry includes state-sequence detector");

        ApiDtos.EntryDto stated = entry("e-state", "com.example.OrderApi", "POST", "/order/draft",
                List.of(), List.of("state=DRAFT"));
        ApiDtos.EntryDto submit = entry("e-submit", "com.example.OrderApi", "POST", "/order/submit",
                List.of(), List.of());
        ApiDtos.EntryDto quota = entry("e-quota", "com.example.WalletApi", "POST", "/wallet/credit",
                List.of(), List.of());
        List<SecurityHypothesis> positive = new StateSequenceDetector().analyze(ctx(
                List.of(stated, submit, quota), List.of()));
        check(positive.stream().anyMatch(h -> h.family() == HypothesisFamily.STATE),
                "StateSequence positive: STATE family");
        check(positive.stream().anyMatch(h ->
                        StateSequenceDetector.PROP_STATE_TRANSITION_GAP.equals(h.securityProperty())),
                "StateSequence positive: state transition gap");
        check(positive.stream().anyMatch(h ->
                        StateSequenceDetector.PROP_REPEAT_SUBMIT.equals(h.securityProperty())),
                "StateSequence positive: repeat submit");
        check(positive.stream().anyMatch(h ->
                        StateSequenceDetector.PROP_QUOTA_INVARIANT.equals(h.securityProperty())),
                "StateSequence positive: quota invariant");

        ApiDtos.EntryDto safeSubmit = entry("e-safe", "com.example.OrderApi", "POST", "/order/submit",
                List.of("name=Idempotency-Key"), List.of("state=DRAFT", "idempotent"));
        List<SecurityHypothesis> negative = new StateSequenceDetector().analyze(ctx(
                List.of(safeSubmit), List.of()));
        check(negative.isEmpty(), "StateSequence negative: state+idempotency present");
    }

    private static void verifyConcurrencyDetector() {
        check(DetectorRegistry.defaults().detectors().stream()
                        .anyMatch(d -> DetectorIds.CONCURRENCY_RESOURCE.equals(d.id())),
                "registry includes concurrency-resource detector");

        BytecodeFactIndex.InstructionEvidence ev = new BytecodeFactIndex.InstructionEvidence(
                "com/example/SharedStore", "update", "()V", 0, 0);
        List<BytecodeFactIndex.CallEdge> edges = List.of(
                edge("com/example/SharedStore", "update", "java/io/File", "exists", ev),
                edge("com/example/SharedStore", "update", "java/io/File", "delete", ev),
                edge("com/example/SharedStore", "update", "java/lang/Thread", "start", ev),
                edge("com/example/SharedStore", "update", "java/util/HashMap", "put", ev)
        );
        StaticFactSnapshot facts = new StaticFactSnapshot(
                StaticFactSnapshot.COMPLETE, List.of(), null,
                List.of(), List.of(), List.of(), List.of(), edges, List.of(), List.of(), List.of());
        DetectorContext positiveCtx = new DetectorContext(
                "scan-conc", ArtifactUniverse.empty(), facts,
                List.of(), List.of(), List.of(), Map.of(), List.of());
        List<SecurityHypothesis> positive = new ConcurrencyResourceDetector().analyze(positiveCtx);
        check(positive.stream().anyMatch(h -> h.family() == HypothesisFamily.CONCURRENCY),
                "Concurrency positive: CONCURRENCY family");
        check(positive.stream().anyMatch(h ->
                        ConcurrencyResourceDetector.PROP_TOCTOU.equals(h.securityProperty())),
                "Concurrency positive: TOCTOU");
        check(positive.stream().anyMatch(h ->
                        ConcurrencyResourceDetector.PROP_RACE_WINDOW.equals(h.securityProperty())
                                || ConcurrencyResourceDetector.PROP_LOCK_GAP.equals(h.securityProperty())),
                "Concurrency positive: race or lock gap");

        List<SecurityHypothesis> negative = new ConcurrencyResourceDetector().analyze(ctx(
                List.of(), List.of()));
        check(negative.isEmpty(), "Concurrency negative: empty IR");
    }

    private static void verifyFamilyDynamicConfirmedGate() {
        PathRun injectable = new PathRun(
                "pr-p2", "scan-p2", "entry:GET:/x", IdentityTrack.UNAUTH, "attempt-p2", null,
                "GET", "application/json", "GET /x", PathOutcomeClass.HTTP_OBSERVED, 200,
                true, true,
                List.of(new SqlEvent(
                        "select * from t where id=''\"veyrion-sqli-meta", "", "READ", false, true, "MOCK")),
                "COMPLETED", "DYNAMIC_SUSPECTED", List.of("evidence-dynamic-1"),
                "MOCK", "no credentials");

        check(DynamicConfirmedGate.evaluate(injectable, "'\"veyrion-sqli-meta")
                        == VerificationStatus.DYNAMIC_CONFIRMED,
                "DATAFLOW SQL H3 still confirms");
        check(DynamicConfirmedGate.allowsDynamicConfirmed(HypothesisFamily.DATAFLOW),
                "DATAFLOW may reach DYNAMIC_CONFIRMED");

        for (HypothesisFamily family : List.of(
                HypothesisFamily.GUARD_COVERAGE,
                HypothesisFamily.STATE,
                HypothesisFamily.TYPESTATE,
                HypothesisFamily.CONCURRENCY,
                HypothesisFamily.CONFIG,
                HypothesisFamily.UNKNOWN)) {
            check(!DynamicConfirmedGate.allowsDynamicConfirmed(family),
                    family + " cannot allow DYNAMIC_CONFIRMED until audit");
            check(DynamicConfirmedGate.evaluate(injectable, "'\"veyrion-sqli-meta", family)
                            == VerificationStatus.DYNAMIC_SUSPECTED,
                    family + " evaluate fail-closed at DYNAMIC_SUSPECTED");
            check(DynamicConfirmedGate.capForFamily(VerificationStatus.DYNAMIC_CONFIRMED, family)
                            == VerificationStatus.DYNAMIC_SUSPECTED,
                    family + " capForFamily clamps DYNAMIC_CONFIRMED");
        }
        check(DynamicConfirmedGate.capForFamily(VerificationStatus.VERIFIED, HypothesisFamily.DATAFLOW)
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "VERIFIED remains closed even for DATAFLOW");
    }

    private static void verifyEntryProvidersRegisterAndUnload() {
        ProviderRegistry.resetForTests();
        Set<String> ids = ProviderRegistry.providerIds();
        check(ids.contains(ServletFilterEntryProvider.ID), "Servlet/Filter EntryProvider registered");
        check(ids.contains(WebFluxEntryProvider.ID), "WebFlux EntryProvider registered");
        check(ids.contains(MessageListenerEntryProvider.ID), "Listener EntryProvider registered");
        check(ids.contains(ScheduledEntryProvider.ID), "Scheduled EntryProvider registered");
        check(ids.contains(WebSocketRpcEntryProvider.ID), "WebSocket/RPC EntryProvider registered");
        check(ids.contains(DefaultJvmProviders.ENTRY_ID), "default Spring entry still registered");

        PreAnalysisResult emptyPre = new PreAnalysisResult(
                new EntryCatalog(List.of(), List.of()),
                new DependencyMap(List.of()),
                new SinkCatalog(List.of()),
                new PermissionMatrix(List.of()),
                BytecodeFactIndex.EMPTY);
        ProviderContext emptyCtx = ProviderContext.of(
                "proj-p2", "digest-empty", "scan-empty", null, emptyPre);
        ProviderBundle emptyBundle = ProviderRegistry.collect(emptyCtx);
        check(emptyBundle.entriesFromScope(ServletFilterEntryProvider.ID).isEmpty(),
                "skeleton providers return empty without fixture");

        BytecodeFactIndex fixtureIndex = new BytecodeFactIndex(
                List.of(
                        new BytecodeFactIndex.ClassFact(
                                "com/example/P2FixtureServlet", "jakarta/servlet/http/HttpServlet",
                                List.of(), 1, "fixture"),
                        new BytecodeFactIndex.ClassFact(
                                "com/example/P2FixtureFilter", "java/lang/Object",
                                List.of("jakarta/servlet/Filter"), 1, "fixture"),
                        new BytecodeFactIndex.ClassFact(
                                "com/example/P2WebFluxHandler", "java/lang/Object",
                                List.of("org/springframework/web/reactive/function/server/HandlerFunction"),
                                1, "fixture"),
                        new BytecodeFactIndex.ClassFact(
                                "com/example/P2FixtureListener", "java/lang/Object",
                                List.of("jakarta/jms/MessageListener"), 1, "fixture"),
                        new BytecodeFactIndex.ClassFact(
                                "com/example/P2WebSocketHandler", "java/lang/Object",
                                List.of("org/springframework/web/socket/WebSocketHandler"), 1, "fixture"),
                        new BytecodeFactIndex.ClassFact(
                                "com/example/P2GrpcService", "java/lang/Object",
                                List.of("io/grpc/BindableService"), 1, "fixture")
                ),
                List.of(),
                List.of(new BytecodeFactIndex.MethodFact(
                        "com/example/P2ScheduledJobs", "cronRefresh", "()V", 1, "fixture")),
                List.of(), List.of(), List.of());
        PreAnalysisResult fixturePre = new PreAnalysisResult(
                new EntryCatalog(List.of(), List.of()),
                new DependencyMap(List.of()),
                new SinkCatalog(List.of()),
                new PermissionMatrix(List.of()),
                fixtureIndex);
        ProviderContext fixtureCtx = ProviderContext.of(
                "proj-p2", "digest-fixture", "scan-fixture", null, fixturePre);
        ProviderBundle withFixture = ProviderRegistry.collect(fixtureCtx);
        check(!withFixture.entriesFromScope(ServletFilterEntryProvider.ID).isEmpty(),
                "Servlet/Filter fixture hit");
        check(!withFixture.entriesFromScope(WebFluxEntryProvider.ID).isEmpty(),
                "WebFlux fixture hit");
        check(!withFixture.entriesFromScope(MessageListenerEntryProvider.ID).isEmpty(),
                "Listener fixture hit");
        check(!withFixture.entriesFromScope(ScheduledEntryProvider.ID).isEmpty(),
                "Scheduled fixture hit");
        check(!withFixture.entriesFromScope(WebSocketRpcEntryProvider.ID).isEmpty(),
                "WebSocket/RPC fixture hit");

        int beforeUnload = withFixture.entries().size();
        check(ProviderRegistry.unregisterById(ServletFilterEntryProvider.ID),
                "unregister Servlet/Filter provider");
        ProviderBundle afterUnload = ProviderRegistry.collect(fixtureCtx);
        check(afterUnload.entriesFromScope(ServletFilterEntryProvider.ID).isEmpty(),
                "unload isolates Servlet/Filter scope");
        check(afterUnload.entries().size() < beforeUnload,
                "unload reduces entry contributions");
        check(!afterUnload.entriesFromScope(WebFluxEntryProvider.ID).isEmpty(),
                "other EntryProviders unaffected after unload");
        check(ProviderRegistry.providerIds().contains(DefaultJvmProviders.ENTRY_ID),
                "default Spring entry survives unload");
    }

    private static DetectorContext ctx(List<ApiDtos.EntryDto> entries,
                                       List<BytecodeFactIndex.CallEdge> edges) {
        StaticFactSnapshot facts = edges == null || edges.isEmpty()
                ? new StaticFactSnapshot(StaticFactSnapshot.COMPLETE, List.of(), null)
                : new StaticFactSnapshot(
                StaticFactSnapshot.COMPLETE, List.of(), null,
                List.of(), List.of(), List.of(), List.of(), edges, List.of(), List.of(), List.of());
        return new DetectorContext(
                "scan-p2", ArtifactUniverse.empty(), facts,
                entries, List.of(), List.of(), Map.of(), List.of());
    }

    private static ApiDtos.EntryDto entry(String id, String declaringClass, String method, String route,
                                          List<String> parameters, List<String> preconditions) {
        return new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION, "p", "digest", "scan-p2", id, "HTTP", method, route,
                declaringClass, "module", parameters, preconditions, ApiDtos.STATIC_INFERRED,
                0.9, 0, List.of("ev-" + id));
    }

    private static BytecodeFactIndex.CallEdge edge(String callerOwner, String callerName,
                                                   String targetOwner, String targetName,
                                                   BytecodeFactIndex.InstructionEvidence evidence) {
        return new BytecodeFactIndex.CallEdge(
                callerOwner, callerName, "()V",
                targetOwner, targetName, "()V",
                BytecodeFactIndex.EdgeKind.DIRECT, "", evidence);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

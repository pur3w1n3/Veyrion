package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.model.PathOutcomeClass;
import com.aq.jvmsentinel.model.PathOutcomeClassifier;
import com.aq.jvmsentinel.model.PathRun;
import com.aq.jvmsentinel.model.SqlEvent;
import com.aq.jvmsentinel.model.VerificationStatus;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Strict, read-only projection of completed authorized artifact traces into public DTOs.
 * It never changes task state and never creates VERIFIED evidence.
 */
public final class TraceProjectionService {
    private static final int MAX_PROJECTED_TASKS = 20_000;
    private static final int MAX_PROJECTED_EVIDENCE = 100_000;
    private static final int MAX_CHUNKS = 10_000;
    private static final int MAX_EVENTS = 10_000;
    private static final int MAX_LINE_BYTES = 64 * 1024;

    private final InMemoryTraceStore traces;
    private final Map<TaskScope, Projection> projections = new ConcurrentHashMap<>();
    private final Map<String, ApiDtos.EvidenceDto> evidence = new ConcurrentHashMap<>();
    /** Optional taskId → experimentPlanId binder (P0-08). */
    private final Map<String, String> taskExperimentPlanIds = new ConcurrentHashMap<>();

    public TraceProjectionService(InMemoryTraceStore traces) {
        this.traces = Objects.requireNonNull(traces, "traces");
    }

    public void bindExperimentPlan(String taskId, String experimentPlanId) {
        if (taskId == null || taskId.isBlank()) {
            return;
        }
        if (experimentPlanId == null || experimentPlanId.isBlank()) {
            taskExperimentPlanIds.remove(taskId);
            return;
        }
        taskExperimentPlanIds.put(taskId, experimentPlanId.trim());
    }

    public String experimentPlanIdForTask(String taskId) {
        if (taskId == null || taskId.isBlank()) {
            return null;
        }
        return taskExperimentPlanIds.get(taskId);
    }

    /**
     * Revalidates and publishes one immutable projection. Invalid traces fail closed and are not retained.
     */
    public synchronized Projection publishCompleted(TaskSnapshot snapshot) {
        Projection projection = project(snapshot);
        Projection prior = projections.get(snapshot.scope());
        int additionalEvidence = prior == null
                ? projection.evidence().size()
                : Math.max(0, projection.evidence().size() - prior.evidence().size());
        if (prior == null && projections.size() >= MAX_PROJECTED_TASKS) {
            throw new IllegalStateException("dynamic projection task limit reached");
        }
        if (evidence.size() + additionalEvidence > MAX_PROJECTED_EVIDENCE) {
            throw new IllegalStateException("dynamic projection evidence limit reached");
        }
        if (prior != null) {
            for (String id : prior.evidence().keySet()) evidence.remove(id, prior.evidence().get(id));
        }
        projections.put(snapshot.scope(), projection);
        projection.evidence().forEach(evidence::putIfAbsent);
        return projection;
    }

    public Projection project(TaskSnapshot snapshot) {
        requireEligible(snapshot);
        TraceManifest manifest = traces.manifest(snapshot.scope());
        List<TraceChunk> chunks = traces.readChunks(snapshot.scope(), MAX_CHUNKS,
                snapshot.spec().resourceBudget().maxTraceBytes());
        return project(snapshot, manifest, chunks);
    }

    /** Visible for contract tests and alternate immutable trace backends. */
    public Projection project(TaskSnapshot snapshot, TraceManifest manifest, List<TraceChunk> chunks) {
        requireEligible(snapshot);
        return projectBody(snapshot, manifest, chunks);
    }

    private Projection projectBody(TaskSnapshot snapshot, TraceManifest manifest, List<TraceChunk> chunks) {
        Objects.requireNonNull(manifest, "manifest");
        Objects.requireNonNull(chunks, "chunks");
        validateChain(snapshot, manifest, chunks);

        List<EventWithDigest> events = parseEvents(chunks, snapshot.spec().resourceBudget().maxTraceBytes());
        List<ApiDtos.PathStepDto> steps = new ArrayList<>(events.size());
        List<String> refs = new ArrayList<>(events.size());
        Map<String, ApiDtos.EvidenceDto> projectedEvidence = new LinkedHashMap<>();
        Map<String, List<ApiDtos.PathStepDto>> routeSteps = new LinkedHashMap<>();
        Map<String, List<String>> routeRefs = new LinkedHashMap<>();
        // Request-window SQL only (P0-06): never copy the full task JDBC list onto every HTTP PathRun.
        // When correlationId is present on HTTP/JDBC, only same-correlation SQL joins the PathRun.
        List<PendingSql> pendingSql = new ArrayList<>();
        List<SqlEvent> orphanSql = new ArrayList<>();
        List<ApiDtos.PathRunDto> pathRuns = new ArrayList<>();
        Set<String> springBoundRouteKeys = new HashSet<>();
        String scopeDigest = WorkerContracts.sha256((snapshot.scope().projectId() + "\n"
                + snapshot.scope().artifactDigest() + "\n" + snapshot.scope().scanId() + "\n"
                + snapshot.scope().taskId()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        int httpAttempt = 0;
        for (EventWithDigest item : events) {
            AgentJsonlTraceConverter.AgentEvent event = item.event();
            String evidenceId = "evidence-dynamic-" + scopeDigest + "-" + event.sequence();
            String kind = switch (event.eventType()) {
                case "AGENT_STARTED", "HTTP" -> "entry";
                case "CLASS_LOAD", "INSTRUMENTATION_CAPABILITY", "INSTRUMENTATION_ERROR",
                        "BRANCH_COVERAGE" -> "transform";
                case "HTTP_CLIENT", "FILE", "JDBC" -> "dependency";
                case "PROCESS" -> "sink";
                default -> throw new IllegalArgumentException("unsupported Agent event type");
            };
            String symbol = event.className().isBlank() ? event.method()
                    : event.method().isBlank() ? event.className()
                    : event.className() + "#" + event.method();
            if (symbol.isBlank()) symbol = event.eventType();
            String route = event.detail().getOrDefault("route", "");
            String httpMethod = event.detail().getOrDefault("httpMethod", "");
            String summary = event.eventType() + " observed by veyrion-agent at " + symbol;
            String stepDetail = event.eventType() + " observed by veyrion-agent at " + symbol;
            if ("HTTP".equals(event.eventType()) && !route.isBlank()) {
                HttpObservation observation = httpObservation(event.detail(), route, httpMethod);
                summary = "HTTP probe observed " + observation.method() + " "
                        + observation.route() + " (target " + observation.requestTarget() + ") -> "
                        + observation.response() + " at " + symbol;
                String corr = correlationId(event.detail());
                if (!corr.isBlank()) {
                    summary = summary + " correlationId=" + corr;
                }
                stepDetail = summary;
            }
            if ("JDBC".equals(event.eventType())) {
                SqlEvent sqlEvent = sqlEventFromDetail(event.detail());
                if (sqlEvent != null) {
                    pendingSql.add(new PendingSql(sqlEvent, correlationId(event.detail())));
                    String sqlPreview = truncate(sqlEvent.sqlText(), 160);
                    summary = "JDBC " + sqlEvent.readWrite() + " observed (capture="
                            + sqlEvent.captureMode() + ")"
                            + (sqlPreview.isBlank() ? "" : ": " + sqlPreview);
                    String corr = correlationId(event.detail());
                    if (!corr.isBlank()) {
                        summary = summary + " correlationId=" + corr;
                    }
                } else {
                    String capture = event.detail().getOrDefault("captureMode", "UNKNOWN");
                    String protocolMeta = event.detail().getOrDefault("summary",
                            event.detail().getOrDefault("operation", ""));
                    summary = "JDBC dependency meta observed (capture=" + capture + ")"
                            + (protocolMeta.isBlank() ? "" : ": " + truncate(protocolMeta, 160));
                }
                stepDetail = summary;
            }
            String snapshotRef = "task:" + snapshot.scope().taskId()
                    + ";digest:" + item.chunkDigest() + ";sequence:" + event.sequence();
            ApiDtos.EvidenceDto evidenceDto = new ApiDtos.EvidenceDto(
                    ApiDtos.SCHEMA_VERSION, snapshot.scope().projectId(),
                    snapshot.scope().artifactDigest(), snapshot.scope().scanId(),
                    evidenceId, event.provenanceKind(), "veyrion-agent", 0.75,
                    summary, event.timestamp(), "veyrion-agent/1",
                    "none", snapshotRef, ApiDtos.MOCK, "DYNAMIC_SUSPECTED");
            projectedEvidence.put(evidenceId, evidenceDto);
            refs.add(evidenceId);
            ApiDtos.PathStepDto step = new ApiDtos.PathStepDto(
                    event.eventType(), stepDetail, kind, "done", List.of(evidenceId),
                    "DYNAMIC_SUSPECTED", event.provenanceKind(), event.eventType(), event.sequence());
            steps.add(step);
            if ("HTTP".equals(event.eventType())) {
                rememberSpringParameterBound(event.detail(), route, httpMethod, springBoundRouteKeys);
            }
            if (isProbeHttpEvent(event) && !route.isBlank()) {
                String routeKey = (httpMethod.isBlank() ? "GET" : httpMethod) + " " + route;
                routeSteps.computeIfAbsent(routeKey, ignored -> new ArrayList<>()).add(step);
                routeRefs.computeIfAbsent(routeKey, ignored -> new ArrayList<>()).add(evidenceId);
                String httpCorr = correlationId(event.detail());
                List<SqlEvent> windowSql = new ArrayList<>();
                List<PendingSql> retained = new ArrayList<>();
                for (PendingSql pending : pendingSql) {
                    if (httpCorr.isBlank()) {
                        // Request-window mode: consume all pending SQL into the next HTTP PathRun.
                        windowSql.add(pending.event());
                    } else if (pending.correlationId().isBlank()) {
                        // HTTP is correlated; uncorrelated SQL must not cross-attach.
                        orphanSql.add(pending.event());
                    } else if (httpCorr.equals(pending.correlationId())) {
                        windowSql.add(pending.event());
                    } else {
                        // Keep other correlations for a later HTTP PathRun.
                        retained.add(pending);
                    }
                }
                pendingSql.clear();
                pendingSql.addAll(retained);
                pathRuns.add(pathRunFromHttp(
                        snapshot, event, evidenceId, httpAttempt++, List.copyOf(windowSql),
                        springBoundRouteKeys));
            }
            if ("BRANCH_COVERAGE".equals(event.eventType()) && !pathRuns.isEmpty()) {
                ApiDtos.PathRunDto last = pathRuns.remove(pathRuns.size() - 1);
                pathRuns.add(mergeBranchCoverage(last, event));
            }
        }
        for (PendingSql pending : pendingSql) {
            orphanSql.add(pending.event());
        }
        ApiDtos.PathDto path = new ApiDtos.PathDto(
                ApiDtos.SCHEMA_VERSION, snapshot.scope().projectId(),
                snapshot.scope().artifactDigest(), snapshot.scope().scanId(),
                "path-dynamic-" + snapshot.scope().taskId(), snapshot.spec().targetEntryId(),
                "DYNAMIC_SUSPECTED", ApiDtos.MOCK, List.of(), "COMPLETED",
                refs, steps, snapshot.scope().taskId(), false,
                snapshot.spec().requiredCapability().name(),
                snapshot.spec().requiredCapability().name() + "_COMPLETED");
        List<ApiDtos.PathDto> paths = new ArrayList<>();
        paths.add(path);
        int routeIndex = 0;
        for (Map.Entry<String, List<ApiDtos.PathStepDto>> entry : routeSteps.entrySet()) {
            String routeKey = entry.getKey();
            String pathId = "path-dynamic-" + snapshot.scope().taskId() + "-route-" + routeIndex++;
            paths.add(new ApiDtos.PathDto(
                    ApiDtos.SCHEMA_VERSION, snapshot.scope().projectId(),
                    snapshot.scope().artifactDigest(), snapshot.scope().scanId(),
                    pathId, snapshot.spec().targetEntryId(),
                    "DYNAMIC_SUSPECTED", ApiDtos.MOCK, List.of(routeKey), "COMPLETED",
                    List.copyOf(routeRefs.getOrDefault(routeKey, List.of())),
                    List.copyOf(entry.getValue()), snapshot.scope().taskId(), false,
                    snapshot.spec().requiredCapability().name(),
                    snapshot.spec().requiredCapability().name() + "_COMPLETED"));
        }
        // Flood / cold-start tasks may emit JDBC/Agent evidence without HTTP events.
        // Still materialize one PathRun so AI tools and dashboard retain SQL detail.
        if (pathRuns.isEmpty()) {
            pathRuns.add(taskLevelPathRun(snapshot, refs, orphanSql));
        }
        return new Projection(snapshot.scope(), path, List.copyOf(paths), List.copyOf(pathRuns),
                projectedEvidence, snapshot.updatedAt().toString());
    }

    public List<ApiDtos.PathRunDto> pathRunsForScan(String projectId, String artifactDigest, String scanId) {
        return projections.values().stream()
                .filter(value -> value.scope().projectId().equals(projectId)
                        && value.scope().artifactDigest().equals(artifactDigest)
                        && value.scope().scanId().equals(scanId))
                .sorted(Comparator.comparing(Projection::completedAt).thenComparing(x -> x.scope().taskId()))
                .flatMap(value -> value.pathRuns().stream())
                .toList();
    }

    public List<ApiDtos.PathRunDto> pathRunsForTask(TaskScope scope) {
        Objects.requireNonNull(scope, "scope");
        Projection projection = projections.get(scope);
        return projection == null ? List.of() : projection.pathRuns();
    }

    private ApiDtos.PathRunDto taskLevelPathRun(
            TaskSnapshot snapshot, List<String> evidenceRefs, List<SqlEvent> jdbcSql) {
        List<SqlEvent> sqlCopy = List.copyOf(jdbcSql);
        String entryRef = "entry:" + snapshot.spec().targetEntryId();
        String stop = snapshot.stopReason() == null ? "COMPLETED" : snapshot.stopReason().name();
        String summary = "task observation without HTTP events; sqlEventCount=" + sqlCopy.size()
                + " evidenceCount=" + evidenceRefs.size();
        PathOutcomeClass outcome = sqlCopy.isEmpty()
                ? PathOutcomeClass.UNKNOWN
                : PathOutcomeClass.DEPENDENCY_MOCK_GAP;
        boolean hasSqlSignal = !sqlCopy.isEmpty();
        String verificationStatus = verificationStatusFor(outcome, -1, null, hasSqlSignal);
        PathRun provisional = new PathRun(
                "pathrun-" + snapshot.scope().taskId() + "-task",
                snapshot.scope().scanId(), entryRef, IdentityTrack.UNAUTH, "attempt-task",
                Objects.requireNonNullElse(experimentPlanIdForTask(snapshot.scope().taskId()), ""),
                "GET", "application/json", summary, outcome, -1, null, null,
                sqlCopy, stop, verificationStatus,
                List.copyOf(evidenceRefs), ApiDtos.MOCK, "no credentials");
        PathRun gated = DynamicConfirmedGate.apply(provisional, SqlDiffProbe.META_MARKER);
        return toPathRunDto(applyD2Differential(gated));
    }

    private ApiDtos.PathRunDto pathRunFromHttp(
            TaskSnapshot snapshot, AgentJsonlTraceConverter.AgentEvent event,
            String evidenceId, int attempt, List<SqlEvent> jdbcSql,
            Set<String> springBoundRouteKeys) {
        Map<String, String> detail = event.detail();
        String route = detail.getOrDefault("route", "/");
        String method = detail.getOrDefault("httpMethod", "GET");
        String statusText = detail.getOrDefault("status", "UNKNOWN");
        int status = statusText.matches("[1-5][0-9]{2}") ? Integer.parseInt(statusText) : -1;
        String error = detail.getOrDefault("error", "");
        String outcomeText = detail.getOrDefault("outcomeClass", "");
        PathOutcomeClass outcome;
        try {
            outcome = outcomeText.isBlank()
                    ? PathOutcomeClassifier.classify(status, error, "")
                    : PathOutcomeClass.valueOf(outcomeText);
        } catch (IllegalArgumentException ignored) {
            outcome = PathOutcomeClassifier.classify(status, error, "");
        }
        IdentityTrack track;
        try {
            track = IdentityTrack.valueOf(detail.getOrDefault("track", "UNAUTH"));
        } catch (IllegalArgumentException ignored) {
            track = IdentityTrack.UNAUTH;
        }
        String normalizedMethod = method.isBlank() ? "GET" : method.toUpperCase(Locale.ROOT);
        String routeKey = normalizedMethod + " " + route;
        Boolean entryHit = resolveEntryHit(detail, status);
        Boolean parameterBound = resolveParameterBound(
                detail, status, routeKey, springBoundRouteKeys);
        String correlation = correlationId(detail);
        String attemptId = !correlation.isBlank() ? correlation : "attempt-" + attempt;
        String entryRef = "entry:" + normalizedMethod + ":" + route;
        List<SqlEvent> sqlCopy = List.copyOf(jdbcSql);
        String planFromDetail = detail.getOrDefault("experimentPlanId", "").trim();
        String boundPlan = experimentPlanIdForTask(snapshot.scope().taskId());
        String experimentPlanId = !planFromDetail.isBlank()
                ? planFromDetail
                : (boundPlan == null ? "" : boundPlan);
        String requestSummary = normalizedMethod + " " + route + " track=" + track.name();
        if (!correlation.isBlank()) {
            requestSummary = requestSummary + " correlationId=" + correlation;
        }
        if (!experimentPlanId.isBlank()) {
            requestSummary = requestSummary + " experimentPlanId=" + experimentPlanId;
        }
        if (parameterBound == null) {
            requestSummary = requestSummary + " parameterBound=unknown";
        }
        String stopReason = outcome.name();
        if (parameterBound == null && status >= 200 && status < 500 && status != 404) {
            stopReason = outcome.name() + ";parameterBound=unknown";
        }
        PathRun provisional = new PathRun(
                "pathrun-" + snapshot.scope().taskId() + "-" + attempt,
                snapshot.scope().scanId(), entryRef, track, attemptId,
                experimentPlanId,
                normalizedMethod,
                "application/json",
                requestSummary,
                outcome, status, entryHit, parameterBound,
                sqlCopy, stopReason,
                verificationStatusFor(outcome, status, entryHit, !sqlCopy.isEmpty()),
                List.of(evidenceId), ApiDtos.MOCK,
                track == IdentityTrack.UNAUTH ? "no credentials" : "synthetic identity");
        String marker = detail.getOrDefault("sqlProbeMarker", SqlDiffProbe.META_MARKER);
        PathRun gated = DynamicConfirmedGate.apply(provisional, marker);
        return toPathRunDto(applyD2Differential(gated));
    }

    private static boolean isProbeHttpEvent(AgentJsonlTraceConverter.AgentEvent event) {
        if (event == null || !"HTTP".equals(event.eventType())) return false;
        Map<String, String> detail = event.detail();
        String captureMode = detail.getOrDefault("captureMode", "");
        if ("LOOPBACK_HTTP_PROBE".equals(captureMode)) return true;
        if (!captureMode.isBlank()) return false;
        if ("com.aq.jvmsentinel.agent.LoopbackHttpProbe".equals(event.className())
                && "main".equals(event.method())) {
            return true;
        }
        String statusText = detail.getOrDefault("status", "");
        String requestTarget = detail.getOrDefault("requestTarget", "");
        String port = detail.getOrDefault("port", "");
        return !statusText.isBlank() && !requestTarget.isBlank() && port.matches("[0-9]{1,5}");
    }

    /**
     * P0-20: DYNAMIC_SUSPECTED only when a real HTTP/effect observation exists.
     * {@code httpStatus=-1}, UNKNOWN/timeout/MOCK-gap/no-bind, AUTH_CHALLENGE (401/403 wall)
     * without effect, and empty signals stay UNREACHED. Auth-wall floods are diagnostics
     * ({@code outcomeClass=AUTH_CHALLENGE} retained for contrast); they are not suspected vulns.
     */
    static String verificationStatusFor(PathOutcomeClass outcome, int httpStatus) {
        return verificationStatusFor(outcome, httpStatus, null, false);
    }

    static String verificationStatusFor(PathOutcomeClass outcome, int httpStatus,
                                        Boolean entryHit, boolean hasEffectOrSqlSignal) {
        if (outcome == null || isDiagnosticUnreached(outcome)) {
            return ApiDtos.UNREACHED;
        }
        if (httpStatus < 0) {
            return ApiDtos.UNREACHED;
        }
        // Auth challenge alone (filter hit, no business bind/effect) is not a success path.
        if (outcome == PathOutcomeClass.AUTH_CHALLENGE) {
            return hasEffectOrSqlSignal
                    ? VerificationStatus.DYNAMIC_SUSPECTED.name()
                    : ApiDtos.UNREACHED;
        }
        if (Boolean.TRUE.equals(entryHit) || hasEffectOrSqlSignal) {
            return VerificationStatus.DYNAMIC_SUSPECTED.name();
        }
        if (outcome == PathOutcomeClass.HTTP_OBSERVED
                && httpStatus >= 200 && httpStatus < 500 && httpStatus != 404) {
            return VerificationStatus.DYNAMIC_SUSPECTED.name();
        }
        return ApiDtos.UNREACHED;
    }

    private static boolean isDiagnosticUnreached(PathOutcomeClass outcome) {
        return switch (outcome) {
            case COLD_START, BUSINESS_TIMEOUT, TRANSPORT_ERROR, PROBE_BUDGET,
                    IDENTITY_UNAVAILABLE, UNKNOWN, DEPENDENCY_MOCK_GAP, REACHED_NO_BIND -> true;
            default -> false;
        };
    }

    /**
     * Prefer explicit event detail; otherwise honest status heuristics.
     * Never invent {@code parameterBound=true} without observation or Spring handler evidence.
     */
    static Boolean resolveEntryHit(Map<String, String> detail, int status) {
        Boolean explicit = parseTriState(detail == null ? null : detail.get("entryHit"));
        if (explicit != null) return explicit;
        if (status == 404 || status == 405) return Boolean.FALSE;
        if (status == 401 || status == 403) return Boolean.TRUE;
        if (status >= 200 && status < 400) return Boolean.TRUE;
        // Timeout / connect / other statuses: unknown rather than inventing a hit.
        return null;
    }

    static Boolean resolveParameterBound(Map<String, String> detail, int status,
                                          String routeKey, Set<String> springBoundRouteKeys) {
        Boolean explicit = parseTriState(detail == null ? null : detail.get("parameterBound"));
        if (explicit != null) return explicit;
        if (status == 404 || status == 405) return Boolean.FALSE;
        if (springBoundRouteKeys != null && routeKey != null && springBoundRouteKeys.contains(routeKey)) {
            return Boolean.TRUE;
        }
        // 2xx with only synthetic empty/marker request still leaves binding unobserved.
        return null;
    }

    static Boolean parseTriState(String value) {
        if (value == null || value.isBlank()) return null;
        if ("true".equalsIgnoreCase(value)) return Boolean.TRUE;
        if ("false".equalsIgnoreCase(value)) return Boolean.FALSE;
        return null;
    }

    private static void rememberSpringParameterBound(Map<String, String> detail, String route,
                                                      String httpMethod, Set<String> springBoundRouteKeys) {
        if (detail == null || springBoundRouteKeys == null) return;
        if (!"SPRING_MAPPING_ANNOTATION".equals(detail.get("captureMode"))) return;
        if (!Boolean.TRUE.equals(parseTriState(detail.get("parameterBound")))) return;
        if (route == null || route.isBlank()) return;
        String method = httpMethod == null || httpMethod.isBlank()
                ? "GET" : httpMethod.toUpperCase(Locale.ROOT);
        springBoundRouteKeys.add(method + " " + route);
    }

    /**
     * D2: when a task PathRun carries both a benign statement and a META_MARKER statement,
     * attach a bounded structure-influence summary. Never upgrades to VERIFIED; H3 remains
     * sole DYNAMIC_CONFIRMED upgrade via {@link DynamicConfirmedGate}.
     */
    static PathRun applyD2Differential(PathRun run) {
        if (run == null || run.sqlEvents() == null || run.sqlEvents().size() < 2) {
            return run;
        }
        SqlEvent benign = null;
        SqlEvent meta = null;
        String needle = SqlDiffProbe.META_MARKER.toLowerCase(Locale.ROOT);
        for (SqlEvent event : run.sqlEvents()) {
            if (event == null || event.sqlText() == null || event.sqlText().isBlank()) continue;
            String sql = event.sqlText().toLowerCase(Locale.ROOT);
            boolean hasMeta = sql.contains(needle) || event.maliciousFragmentPresent();
            if (hasMeta) {
                if (meta == null) meta = event;
            } else if (benign == null) {
                benign = event;
            }
        }
        if (benign == null || meta == null) return run;
        SqlDiffProbe.DiffResult diff = SqlDiffProbe.compare(benign, meta);
        // D2 itself is capped at DYNAMIC_SUSPECTED; preserve any prior H3 DYNAMIC_CONFIRMED.
        String tag = "D2: structureInfluenced=" + diff.structureInfluenced() + " (MOCK)";
        String base = run.requestSummary() == null ? "" : run.requestSummary().trim();
        if (base.contains("D2: structureInfluenced=")) return run;
        String summary = base.isBlank() ? tag : truncate(base + "; " + tag, 512);
        String status = run.verificationStatus();
        if (VerificationStatus.VERIFIED.name().equals(status)) {
            status = VerificationStatus.DYNAMIC_SUSPECTED.name();
        }
        return new PathRun(
                run.pathRunId(), run.scanId(), run.entrypointRef(), run.track(), run.attemptId(),
                run.experimentPlanId(), run.method(), run.contentType(), summary,
                run.outcomeClass(), run.httpStatus(), run.entryHit(), run.parameterBound(),
                run.sqlEvents(), run.stopReason(), status, run.evidenceRefs(),
                run.identityProvenance(), run.identityPrecondition(), run.branchHitMap());
    }

    private static ApiDtos.PathRunDto toPathRunDto(PathRun gated) {
        List<ApiDtos.SqlEventDto> sqlDtos = gated.sqlEvents().stream()
                .map(sql -> new ApiDtos.SqlEventDto(sql.sqlText(), sql.parameterSummary(),
                        sql.readWrite(), sql.parameterized(), sql.maliciousFragmentPresent(),
                        sql.captureMode()))
                .toList();
        return new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, gated.pathRunId(), gated.scanId(), gated.entrypointRef(),
                gated.track().name(), gated.attemptId(), gated.experimentPlanId(),
                gated.method(), gated.contentType(), gated.requestSummary(),
                gated.outcomeClass().name(), gated.httpStatus(), gated.entryHit(),
                gated.parameterBound(), sqlDtos, gated.stopReason(), gated.verificationStatus(),
                gated.evidenceRefs(), gated.identityProvenance(), gated.identityPrecondition(),
                gated.branchHitMap());
    }

    /**
     * BRANCH_COVERAGE events flush after their HTTP observation; attach hits to the latest PathRun.
     * Encoding: COMMA_SEPARATED_HIT_INDICES in detail.hits (chunked by EventWriter limits).
     */
    public static ApiDtos.PathRunDto mergeBranchCoverage(
            ApiDtos.PathRunDto run, AgentJsonlTraceConverter.AgentEvent event) {
        if (run == null || event == null) return run;
        Map<String, String> detail = event.detail();
        String classname = detail.getOrDefault("classname",
                event.className() == null ? "" : event.className());
        String methodDesc = detail.getOrDefault("methodDesc",
                event.method() == null ? "" : event.method());
        if (classname.isBlank() || methodDesc.isBlank()) return run;
        String key = classname.replace('/', '.') + "#" + methodDesc;
        List<Integer> hits = decodeHitIndices(detail.getOrDefault("hits", ""));
        if (hits.isEmpty()) return run;
        Map<String, List<Integer>> merged = new LinkedHashMap<>(run.branchHitMap());
        LinkedHashSet<Integer> combined = new LinkedHashSet<>(merged.getOrDefault(key, List.of()));
        combined.addAll(hits);
        List<Integer> ordered = new ArrayList<>(combined);
        ordered.sort(Integer::compareTo);
        merged.put(key, List.copyOf(ordered));
        return new ApiDtos.PathRunDto(
                run.schemaVersion(), run.pathRunId(), run.scanId(), run.entrypointRef(),
                run.track(), run.attemptId(), run.experimentPlanId(), run.method(),
                run.contentType(), run.requestSummary(), run.outcomeClass(), run.httpStatus(),
                run.entryHit(), run.parameterBound(), run.sqlEvents(), run.stopReason(),
                run.verificationStatus(), run.evidenceRefs(), run.identityProvenance(),
                run.identityPrecondition(), Map.copyOf(merged));
    }

    static List<Integer> decodeHitIndices(String encoded) {
        if (encoded == null || encoded.isBlank()) return List.of();
        List<Integer> hits = new ArrayList<>();
        for (String part : encoded.split(",")) {
            String token = part.trim();
            if (token.isEmpty() || !token.matches("[0-9]{1,9}")) continue;
            hits.add(Integer.parseInt(token));
            if (hits.size() >= 4_096) break;
        }
        return List.copyOf(hits);
    }

    /**
     * Projects only statement-level JDBC observations into PathRun.sqlEvents (D1).
     * Protocol listen/handshake meta ({@code port=6379}, {@code sqlClass=…,bytes=N}, Redis RESP,
     * auth accept) stays on dependency evidence steps and must not pretend to be SQL text.
     */
    static String correlationId(Map<String, String> detail) {
        if (detail == null) return "";
        String value = detail.getOrDefault("correlationId", "").trim();
        if (value.isEmpty() || value.length() > 64) return "";
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")) return "";
        return value;
    }

    private record PendingSql(SqlEvent event, String correlationId) {
        private PendingSql {
            event = Objects.requireNonNull(event, "event");
            correlationId = correlationId == null ? "" : correlationId;
        }
    }

    private static SqlEvent sqlEventFromDetail(Map<String, String> detail) {
        if (!isStatementSqlObservation(detail)) return null;
        String sql = detail.get("sql").trim();
        String rw = detail.getOrDefault("readWrite", inferReadWrite(sql));
        boolean parameterized = "true".equalsIgnoreCase(detail.getOrDefault("parameterized", "false"))
                || sql.contains("?");
        boolean malicious = sql.toLowerCase(Locale.ROOT).contains(SqlDiffProbe.META_MARKER.toLowerCase(Locale.ROOT))
                || "true".equalsIgnoreCase(detail.getOrDefault("maliciousFragmentPresent", "false"));
        String parameterSummary = detail.getOrDefault("parameterSummary", "");
        if (parameterSummary.isBlank()) {
            parameterSummary = statementMetaSummary(detail);
        }
        String captureMode = detail.getOrDefault("captureMode",
                detail.getOrDefault("dependencyMode", ApiDtos.MOCK));
        return new SqlEvent(sql, parameterSummary, rw, parameterized, malicious, captureMode);
    }

    private static String statementMetaSummary(Map<String, String> detail) {
        String sqlClass = detail.getOrDefault("sqlClass", "").trim();
        String outcome = detail.getOrDefault("outcome", "").trim();
        if (sqlClass.isBlank() && outcome.isBlank()) return "";
        if (sqlClass.isBlank()) return truncate("outcome=" + outcome, 512);
        if (outcome.isBlank()) return truncate("sqlClass=" + sqlClass, 512);
        return truncate("sqlClass=" + sqlClass + ",outcome=" + outcome, 512);
    }

    /** True only when detail carries truncated statement text usable for D1–D3 / H3. */
    static boolean isStatementSqlObservation(Map<String, String> detail) {
        if (detail == null) return false;
        String sql = detail.get("sql");
        if (sql == null || sql.isBlank()) return false;
        String trimmed = sql.trim();
        if (isProtocolMetaText(trimmed)) return false;
        String protocol = detail.getOrDefault("protocol", "");
        if ("REDIS_RESP".equalsIgnoreCase(protocol)) return false;
        String capture = detail.getOrDefault("captureMode", "");
        if ("DEPENDENCY_PROTOCOL_MOCK".equals(capture) && !looksLikeSqlStatement(trimmed)) {
            return false;
        }
        return looksLikeSqlStatement(trimmed) || trimmed.contains("?");
    }

    private static boolean isProtocolMetaText(String value) {
        String lower = value.toLowerCase(Locale.ROOT);
        return lower.startsWith("port=")
                || lower.startsWith("sqlclass=")
                || lower.contains("accepted-without-credential")
                || lower.equals("client-budget")
                || lower.equals("operation-limit")
                || lower.equals("ok")
                || lower.equals("closed")
                || lower.equals("reset")
                || lower.equals("accepted");
    }

    private static boolean looksLikeSqlStatement(String value) {
        String lower = value.trim().toLowerCase(Locale.ROOT);
        return lower.startsWith("select") || lower.startsWith("insert") || lower.startsWith("update")
                || lower.startsWith("delete") || lower.startsWith("replace") || lower.startsWith("with")
                || lower.startsWith("show") || lower.startsWith("explain") || lower.startsWith("describe")
                || lower.startsWith("desc") || lower.startsWith("set ") || lower.startsWith("use ")
                || lower.startsWith("call ") || lower.startsWith("create") || lower.startsWith("alter")
                || lower.startsWith("drop") || lower.startsWith("truncate") || lower.startsWith("begin")
                || lower.startsWith("commit") || lower.startsWith("rollback") || lower.startsWith("start ");
    }

    private static String inferReadWrite(String sql) {
        String value = sql == null ? "" : sql.trim().toLowerCase(Locale.ROOT);
        if (value.startsWith("select") || value.startsWith("show") || value.startsWith("explain")
                || value.startsWith("describe") || value.startsWith("desc") || value.startsWith("with")) {
            return "READ";
        }
        if (value.startsWith("insert") || value.startsWith("update") || value.startsWith("delete")
                || value.startsWith("replace") || value.startsWith("create") || value.startsWith("alter")
                || value.startsWith("drop") || value.startsWith("truncate")) {
            return "WRITE";
        }
        return "UNKNOWN";
    }

    private static String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max);
    }

    public List<ApiDtos.PathDto> pathsForScan(String projectId, String artifactDigest, String scanId) {
        return projections.values().stream()
                .filter(value -> value.scope().projectId().equals(projectId)
                        && value.scope().artifactDigest().equals(artifactDigest)
                        && value.scope().scanId().equals(scanId))
                .sorted(Comparator.comparing(Projection::completedAt).thenComparing(x -> x.scope().taskId()))
                .flatMap(value -> value.paths().stream())
                .toList();
    }

    public ApiDtos.EvidenceDto evidence(String evidenceId) {
        return evidenceId == null ? null : evidence.get(evidenceId);
    }

    public List<ApiDtos.EvidenceDto> evidenceForScan(String projectId, String artifactDigest, String scanId) {
        return projections.values().stream()
                .filter(value -> value.scope().projectId().equals(projectId)
                        && value.scope().artifactDigest().equals(artifactDigest)
                        && value.scope().scanId().equals(scanId))
                .sorted(Comparator.comparing(Projection::completedAt).thenComparing(x -> x.scope().taskId()))
                .flatMap(value -> value.evidence().values().stream())
                .toList();
    }

    private static void requireEligible(TaskSnapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot");
        WorkerTaskSpec spec = snapshot.spec();
        boolean externalEligible = spec.authorized()
                && (spec.requiredCapability() == WorkerCapability.TRUSTED_DOCKER
                || spec.requiredCapability() == WorkerCapability.HARDENED_GVISOR
                || spec.requiredCapability() == WorkerCapability.HARDENED_KATA);
        if (snapshot.lifecycle() != TaskLifecycle.COMPLETED
                || snapshot.stopReason() != StopReason.COMPLETED
                || !externalEligible) {
            throw new IllegalArgumentException(
                    "only completed authorized artifact tasks may be projected");
        }
    }

    /**
     * Pre-complete validation (P0-06): project while task is still RUNNING so bad traces
     * can fail closed before lifecycle becomes COMPLETED.
     */
    public Projection validateProjectable(TaskSnapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot");
        WorkerTaskSpec spec = snapshot.spec();
        boolean externalEligible = spec.authorized()
                && (spec.requiredCapability() == WorkerCapability.TRUSTED_DOCKER
                || spec.requiredCapability() == WorkerCapability.HARDENED_GVISOR
                || spec.requiredCapability() == WorkerCapability.HARDENED_KATA);
        if (!externalEligible) {
            throw new IllegalArgumentException("task is not projection-eligible");
        }
        if (snapshot.lifecycle() != TaskLifecycle.RUNNING
                && snapshot.lifecycle() != TaskLifecycle.COMPLETED) {
            throw new IllegalArgumentException("task lifecycle cannot be projected");
        }
        TraceManifest manifest = traces.manifest(snapshot.scope());
        List<TraceChunk> chunks = traces.readChunks(snapshot.scope(), MAX_CHUNKS,
                snapshot.spec().resourceBudget().maxTraceBytes());
        return projectBody(snapshot, manifest, chunks);
    }

    private static void validateChain(TaskSnapshot snapshot, TraceManifest manifest, List<TraceChunk> chunks) {
        TaskScope scope = snapshot.scope();
        if (!scope.equals(manifest.scope())) throw new SecurityException("trace manifest scope mismatch");
        if (chunks.isEmpty() || chunks.size() != manifest.chunks().size() || chunks.size() > MAX_CHUNKS) {
            throw new IllegalArgumentException("trace manifest and chunks do not match");
        }
        long total = 0;
        String previous = null;
        for (int index = 0; index < chunks.size(); index++) {
            TraceChunk chunk = chunks.get(index);
            TraceManifest.ChunkRef ref = manifest.chunks().get(index);
            if (!scope.equals(chunk.scope())) throw new SecurityException("trace chunk scope mismatch");
            byte[] payload = chunk.payload();
            String calculated = TraceChunk.calculateDigest(chunk.schemaVersion(), chunk.scope(), chunk.sequence(),
                    chunk.previousDigest(), chunk.emittedAt(), payload);
            if (chunk.sequence() != index || ref.sequence() != index
                    || !Objects.equals(previous, chunk.previousDigest())
                    || !calculated.equals(chunk.digest())
                    || !chunk.digest().equals(ref.digest())
                    || payload.length != ref.payloadBytes()
                    || !chunk.emittedAt().equals(ref.emittedAt())) {
                throw new SecurityException("trace chain validation failed");
            }
            if (payload.length > snapshot.spec().resourceBudget().maxTraceBytes() - total) {
                throw new IllegalArgumentException("trace exceeds task byte budget");
            }
            total += payload.length;
            previous = chunk.digest();
        }
        if (total != manifest.totalPayloadBytes()
                || total > snapshot.spec().resourceBudget().maxTraceBytes()
                || !Objects.equals(previous, manifest.headDigest())) {
            throw new SecurityException("trace manifest summary mismatch");
        }
    }

    private static List<EventWithDigest> parseEvents(List<TraceChunk> chunks, long maxBytes) {
        List<EventWithDigest> result = new ArrayList<>();
        long bytes = 0;
        long expectedSequence = 0;
        for (TraceChunk chunk : chunks) {
            byte[] payload = chunk.payload();
            if (payload.length == 0 || payload[payload.length - 1] != '\n') {
                throw new IllegalArgumentException("trace chunk must contain complete JSONL lines");
            }
            if (payload.length > maxBytes - bytes) throw new IllegalArgumentException("trace exceeds byte budget");
            bytes += payload.length;
            int start = 0;
            for (int index = 0; index < payload.length; index++) {
                if (payload[index] != '\n') continue;
                int length = index - start;
                if (length <= 0 || length > MAX_LINE_BYTES) {
                    throw new IllegalArgumentException("trace contains an invalid JSONL line length");
                }
                if (result.size() >= MAX_EVENTS) throw new IllegalArgumentException("trace exceeds event limit");
                byte[] line = Arrays.copyOfRange(payload, start, index);
                AgentJsonlTraceConverter.AgentEvent event =
                        AgentJsonlTraceConverter.parseAcceptedLine(line, line.length, expectedSequence);
                expectedSequence = Math.addExact(event.sequence(), 1);
                result.add(new EventWithDigest(event, chunk.digest()));
                start = index + 1;
            }
        }
        if (result.isEmpty()) throw new IllegalArgumentException("trace contains no events");
        return List.copyOf(result);
    }

    private record EventWithDigest(AgentJsonlTraceConverter.AgentEvent event, String chunkDigest) { }

    /**
     * Builds a bounded public view of a loopback probe. Query values are never exposed: only
     * parameter names and value lengths cross the evidence boundary.
     */
    private static HttpObservation httpObservation(Map<String, String> detail, String route,
                                                   String method) {
        String safeRoute = safeRoute(route);
        String rawTarget = detail.getOrDefault("requestTarget", route);
        String safeTarget = safeRequestTarget(rawTarget, safeRoute);
        String safeMethod = safeMethod(method);
        String status = detail.getOrDefault("status", "UNKNOWN");
        String safeStatus = status.matches("[1-5][0-9]{2}") ? "HTTP " + status : "HTTP UNKNOWN";
        String error = detail.getOrDefault("error", "");
        if (!error.isBlank()) {
            String safeError = error.matches("[A-Za-z0-9_.$-]{1,64}") ? error : "ProbeError";
            safeStatus += " (" + safeError + ")";
        }
        return new HttpObservation(safeMethod, safeRoute, safeTarget, safeStatus);
    }

    private static String safeMethod(String method) {
        return method != null && method.matches("(?i)GET|POST|PUT|PATCH|DELETE")
                ? method.toUpperCase(java.util.Locale.ROOT) : "HTTP";
    }

    private static String safeRoute(String route) {
        if (route == null || route.isBlank()) return "/";
        String value = route.length() > 512 ? route.substring(0, 512) : route;
        return value.matches("/[A-Za-z0-9_./{}:-]{0,511}") ? value : "/<redacted-route>";
    }

    private static String safeRequestTarget(String target, String fallbackRoute) {
        if (target == null || target.isBlank()) return fallbackRoute;
        String value = target.length() > 512 ? target.substring(0, 512) : target;
        int queryIndex = value.indexOf('?');
        String targetRoute = queryIndex < 0 ? value : value.substring(0, queryIndex);
        String safeTargetRoute = safeRoute(targetRoute);
        if (queryIndex < 0 || queryIndex == value.length() - 1) return safeTargetRoute;
        String query = value.substring(queryIndex + 1);
        StringBuilder redacted = new StringBuilder(safeTargetRoute).append('?');
        String[] pairs = query.split("&", -1);
        int emitted = 0;
        for (String pair : pairs) {
            if (pair.isBlank() || emitted >= 32) continue;
            int equals = pair.indexOf('=');
            String name = equals < 0 ? pair : pair.substring(0, equals);
            String rawValue = equals < 0 ? "" : pair.substring(equals + 1);
            if (!name.matches("[A-Za-z0-9_:-]{1,64}")) name = "param" + emitted;
            if (emitted > 0) redacted.append('&');
            redacted.append(name).append("=<redacted:length=")
                    .append(Math.min(rawValue.length(), 256)).append('>');
            emitted++;
        }
        return redacted.toString();
    }

    private record HttpObservation(String method, String route, String requestTarget, String response) { }

    public record Projection(TaskScope scope, ApiDtos.PathDto path, List<ApiDtos.PathDto> paths,
                             List<ApiDtos.PathRunDto> pathRuns,
                             Map<String, ApiDtos.EvidenceDto> evidence, String completedAt) {
        public Projection(TaskScope scope, ApiDtos.PathDto path, List<ApiDtos.PathDto> paths,
                          Map<String, ApiDtos.EvidenceDto> evidence, String completedAt) {
            this(scope, path, paths, List.of(), evidence, completedAt);
        }

        public Projection {
            Objects.requireNonNull(scope, "scope");
            Objects.requireNonNull(path, "path");
            paths = List.copyOf(paths == null || paths.isEmpty() ? List.of(path) : paths);
            pathRuns = List.copyOf(pathRuns == null ? List.of() : pathRuns);
            evidence = Map.copyOf(evidence);
            Objects.requireNonNull(completedAt, "completedAt");
        }
    }
}

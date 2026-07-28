package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.model.AuthBypassTechnique;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses and validates AUTH/triage AI-authored bypass PoCs.
 * Accepts Authorization / secondaryAuthorizationHeader (wire: bladeAuthHeader) / JWT /
 * query / body hints under hard bounds;
 * rejects entry escape, oversize, control chars, and destructive unchecked payloads.
 * When a scan has an auth surface (JWT / AUTH_GAP / auth-annotated entries) but AUTH
 * emits no structured PoCs, the server requires a repair re-ask or seeds RULE_GENERATED
 * drafts so DYNAMIC still has candidates — never elevates verification from LLM alone.
 */
public final class AuthBypassFeasibility {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern FENCED_JSON = Pattern.compile(
            "(?is)```(?:json)?\\s*(\\{.*?(?:\"bypassCandidates\"|\"bypassPoCs\").*?})\\s*```");
    public static final String ENFORCEMENT_REQUIRED = "AUTH_BYPASS_POC_REQUIRED";
    public static final String ENFORCEMENT_SEEDED = "AUTH_BYPASS_POC_SEEDED";
    public static final String ENFORCEMENT_SATISFIED = "AUTH_BYPASS_POC_SATISFIED";
    public static final String DRAFT_RULE_GENERATED = "RULE_GENERATED";
    /** DYNAMIC must attempt sandbox_probe when AUTH handed non-empty PoCs. */
    public static final String DYNAMIC_ATTEMPT_REQUIRED = "DYNAMIC_POC_ATTEMPT_REQUIRED";
    public static final String DYNAMIC_ATTEMPT_SEEDED = "DYNAMIC_POC_ATTEMPT_SEEDED";
    public static final String DYNAMIC_ATTEMPT_SATISFIED = "DYNAMIC_POC_ATTEMPT_SATISFIED";
    /** Prompt target band: attempt this many distinct PoCs before narrative-only. */
    public static final int DYNAMIC_POC_PROBE_MIN = 3;
    public static final int DYNAMIC_POC_PROBE_MAX = 8;
    /** Server auto-enqueue fallback cap (wall-clock / scan-busy aware). */
    public static final int DYNAMIC_POC_AUTO_PROBE_MAX = 3;
    /** AUTH must diversify to at least this many mechanism/path keys when surface present. */
    public static final int AUTH_POC_MECHANISM_MIN = 3;
    public static final String CODE_QUERY_REQUIRED = "AUTH_CODE_QUERY_REQUIRED";
    public static final String POC_DIVERSITY_REQUIRED = "AUTH_POC_DIVERSITY_REQUIRED";
    public static final String AUTH_PASS_INITIAL = "AUTH_INITIAL";
    public static final String AUTH_PASS_CONFIRM = "AUTH_BYPASS_CONFIRM";
    public static final String INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE";
    private static final int MAX_SEEDED_ENTRIES = 3;
    private static final int MAX_SEEDED_POCS = 9;

    private AuthBypassFeasibility() { }

    public record ParseResult(
            List<AuthBypassCandidate> candidates,
            List<String> rejected,
            String emptyReason
    ) {
        public ParseResult {
            candidates = List.copyOf(candidates == null ? List.of() : candidates);
            rejected = List.copyOf(rejected == null ? List.of() : rejected);
            emptyReason = emptyReason == null ? "" : emptyReason;
        }
    }

    /**
     * Static auth surface signals that require structured bypass PoCs from AUTH.
     */
    public record AuthSurface(
            boolean present,
            int jwtSinkCount,
            int authGapSinkCount,
            int jwtOrAuthGapFindingCount,
            int authAnnotatedEntryCount,
            List<String> sampleEntryRefs
    ) {
        public AuthSurface {
            sampleEntryRefs = List.copyOf(sampleEntryRefs == null ? List.of() : sampleEntryRefs);
        }

        public boolean present() {
            return present;
        }
    }

    public record EnforcementMeta(
            boolean authSurfacePresent,
            String enforcementCode,
            String pocDraftSource,
            boolean reAskTriggered
    ) {
        public EnforcementMeta {
            enforcementCode = enforcementCode == null ? "" : enforcementCode;
            pocDraftSource = pocDraftSource == null ? "" : pocDraftSource;
        }
    }

    /** P3: AUTH confirm must distinguish static hypothesis from PathRun dynamic contrast. */
    public enum BypassConfirmationStatus {
        HYPOTHESIS,
        DYNAMIC_CONTRAST,
        INSUFFICIENT_EVIDENCE
    }

    public record BypassConfirmation(
            BypassConfirmationStatus status,
            List<String> pathRunRefs
    ) {
        public BypassConfirmation {
            status = status == null ? BypassConfirmationStatus.HYPOTHESIS : status;
            pathRunRefs = List.copyOf(pathRunRefs == null ? List.of() : pathRunRefs);
        }
    }

    public static final String CONFIRMATION_INSUFFICIENT_PREFIX = "[INSUFFICIENT_EVIDENCE]";

    public static ParseResult parseAndValidate(String summaryOrJson, Set<String> allowedEntryRefs) {
        List<String> rejected = new ArrayList<>();
        JsonNode root = extractJson(summaryOrJson);
        if (root == null || root.isMissingNode() || root.isNull()) {
            return new ParseResult(List.of(), List.of("NO_STRUCTURED_BYPASS_BLOCK"),
                    "AUTH output contained no bypassCandidates/bypassPoCs JSON");
        }
        String emptyReason = text(root, "emptyReason");
        if (emptyReason.isBlank()) emptyReason = text(root, "reason");
        JsonNode array = root.get("bypassPoCs");
        if (array == null || !array.isArray()) array = root.get("bypassCandidates");
        if (array == null || !array.isArray()) {
            return new ParseResult(List.of(), List.of("MISSING_BYPASS_POC_ARRAY"),
                    emptyReason.isBlank() ? "bypassPoCs array missing" : emptyReason);
        }
        List<AuthBypassCandidate> accepted = new ArrayList<>();
        Set<String> dedupe = new LinkedHashSet<>();
        for (JsonNode item : array) {
            try {
                AuthBypassCandidate candidate = fromNode(item, allowedEntryRefs);
                String key = key(candidate);
                if (!dedupe.add(key)) {
                    rejected.add("DUPLICATE:" + key);
                    continue;
                }
                accepted.add(candidate);
                if (accepted.size() >= AuthBypassCandidate.MAX_CANDIDATES) break;
            } catch (IllegalArgumentException invalid) {
                rejected.add(invalid.getMessage() == null ? "INVALID_CANDIDATE" : invalid.getMessage());
            }
        }
        if (accepted.isEmpty() && emptyReason.isBlank()) {
            emptyReason = rejected.isEmpty()
                    ? "no feasible bypass PoCs"
                    : "all PoCs rejected by server gate";
        }
        return new ParseResult(accepted, rejected, emptyReason);
    }

    public static AuthBypassCandidate fromPlanPropose(
            String entryRef, String techniqueId, String trackName,
            String rationale, JsonNode evidenceRefs, Double confidence,
            String authorizationHeader, String bladeAuthHeader, String query, String bodyHint,
            Set<String> allowedEntryRefs) {
        IdentityTrack track = resolveTrack(techniqueId, trackName);
        List<String> refs = new ArrayList<>();
        if (evidenceRefs != null && evidenceRefs.isArray()) {
            for (JsonNode ref : evidenceRefs) refs.add(ref.asText());
        }
        AuthBypassCandidate candidate = AuthBypassCandidate.of(
                entryRef,
                techniqueId == null || techniqueId.isBlank() ? "CUSTOM_POC" : techniqueId,
                track,
                rationale,
                refs,
                confidence == null ? 0.35 : confidence,
                authorizationHeader,
                bladeAuthHeader,
                query,
                bodyHint);
        requireAllowedEntry(candidate.entryRef(), allowedEntryRefs);
        return candidate;
    }

    public static List<AuthBypassCandidate> merge(
            List<AuthBypassCandidate> fromTools, ParseResult fromSummary) {
        Map<String, AuthBypassCandidate> merged = new LinkedHashMap<>();
        if (fromTools != null) {
            for (AuthBypassCandidate candidate : fromTools) {
                merged.put(key(candidate), candidate);
            }
        }
        if (fromSummary != null) {
            for (AuthBypassCandidate candidate : fromSummary.candidates()) {
                merged.putIfAbsent(key(candidate), candidate);
            }
        }
        return List.copyOf(merged.values()).stream()
                .limit(AuthBypassCandidate.MAX_CANDIDATES)
                .toList();
    }

    public static ObjectNode toConclusionNode(
            String summary, List<AuthBypassCandidate> candidates, String emptyReason,
            List<String> rejected) {
        return toConclusionNode(summary, candidates, emptyReason, rejected, null);
    }

    public static ObjectNode toConclusionNode(
            String summary, List<AuthBypassCandidate> candidates, String emptyReason,
            List<String> rejected, EnforcementMeta enforcement) {
        return toConclusionNode(summary, candidates, emptyReason, rejected, enforcement, null);
    }

    public static ObjectNode toConclusionNode(
            String summary, List<AuthBypassCandidate> candidates, String emptyReason,
            List<String> rejected, EnforcementMeta enforcement, BypassConfirmation confirmation) {
        ObjectNode node = JSON.createObjectNode();
        node.put("schemaVersion", 1);
        node.put("classification", "INFERENCE");
        node.put("summary", summary == null ? "" : summary);
        node.putArray("evidenceRefs");
        ArrayNode array = node.putArray("bypassPoCs");
        ArrayNode legacy = node.putArray("bypassCandidates");
        boolean seeded = enforcement != null
                && DRAFT_RULE_GENERATED.equals(enforcement.pocDraftSource());
        for (AuthBypassCandidate candidate : candidates == null ? List.<AuthBypassCandidate>of() : candidates) {
            ObjectNode row = toJson(candidate);
            if (seeded) {
                row.put("draftProvenance", DRAFT_RULE_GENERATED);
            }
            array.add(row);
            legacy.add(row.deepCopy());
        }
        if (candidates == null || candidates.isEmpty()) {
            node.put("emptyReason", emptyReason == null || emptyReason.isBlank()
                    ? "no feasible bypass PoCs" : emptyReason);
        } else if (emptyReason != null && !emptyReason.isBlank()) {
            node.put("emptyReason", emptyReason);
        }
        if (rejected != null && !rejected.isEmpty()) {
            ArrayNode rejectedNode = node.putArray("rejectedCandidates");
            rejected.stream().limit(32).forEach(rejectedNode::add);
        }
        node.put("verificationStatus", "INFERENCE");
        node.put("pocOwnership", seeded
                ? "SERVER_SEED_RULE_GENERATED_AFTER_AUTH_GAP"
                : "AI_AUTHORS_SERVER_VALIDATES_DYNAMIC_EXECUTES");
        if (enforcement != null) {
            node.put("authSurfacePresent", enforcement.authSurfacePresent());
            if (!enforcement.enforcementCode().isBlank()) {
                node.put("enforcement", enforcement.enforcementCode());
            }
            if (!enforcement.pocDraftSource().isBlank()) {
                node.put("pocDraftSource", enforcement.pocDraftSource());
            }
            node.put("reAskTriggered", enforcement.reAskTriggered());
        }
        applyBypassConfirmation(node, confirmation);
        return node;
    }

    /**
     * Server evidence gate for AUTH bypass confirmation.
     * Zero PathRun AUTH_CHALLENGE / pass-gate evidence → never DYNAMIC_CONTRAST;
     * claiming confirmed without evidence → INSUFFICIENT_EVIDENCE.
     */
    public static BypassConfirmation evaluateBypassConfirmation(
            String summaryOrJson,
            List<ApiDtos.PathRunDto> pathRuns,
            List<AuthBypassCandidate> claimedCandidates) {
        JsonNode modelConfirmation = extractBypassConfirmationNode(summaryOrJson);
        List<String> evidenceRefs = collectDynamicAuthEvidenceRefs(pathRuns, claimedCandidates);
        boolean claimsConfirmed = claimsBypassConfirmed(summaryOrJson, modelConfirmation);
        String modelStatus = modelConfirmation == null ? "" : text(modelConfirmation, "status");
        boolean modelContrast = "DYNAMIC_CONTRAST".equalsIgnoreCase(modelStatus);
        if (evidenceRefs.isEmpty()) {
            if (claimsConfirmed || modelContrast) {
                return new BypassConfirmation(
                        BypassConfirmationStatus.INSUFFICIENT_EVIDENCE, List.of());
            }
            return new BypassConfirmation(BypassConfirmationStatus.HYPOTHESIS, List.of());
        }
        if (claimsConfirmed || modelContrast) {
            return new BypassConfirmation(
                    BypassConfirmationStatus.DYNAMIC_CONTRAST, evidenceRefs);
        }
        return new BypassConfirmation(BypassConfirmationStatus.HYPOTHESIS, evidenceRefs);
    }

    public static void applyBypassConfirmation(ObjectNode node, BypassConfirmation confirmation) {
        if (node == null || confirmation == null) return;
        ObjectNode block = node.putObject("bypassConfirmation");
        block.put("status", confirmation.status().name());
        ArrayNode refs = block.putArray("pathRunRefs");
        confirmation.pathRunRefs().stream().limit(32).forEach(refs::add);
        // Legacy flat field for dashboards that already read confirmationStatus.
        node.put("confirmationStatus", confirmation.status().name());
        if (confirmation.status() == BypassConfirmationStatus.INSUFFICIENT_EVIDENCE) {
            String summary = node.path("summary").asText("");
            if (!summary.startsWith(CONFIRMATION_INSUFFICIENT_PREFIX)) {
                node.put("summary", CONFIRMATION_INSUFFICIENT_PREFIX
                        + (summary.isBlank() ? "" : " " + summary));
            }
        }
    }

    /**
     * PathRuns that can support dynamic contrast: AUTH_CHALLENGE, or 2xx/3xx on
     * BYPASS_CANDIDATE / ADMIN tracks for claimed entries (when claims are present).
     */
    public static List<String> collectDynamicAuthEvidenceRefs(
            List<ApiDtos.PathRunDto> pathRuns,
            List<AuthBypassCandidate> claimedCandidates) {
        if (pathRuns == null || pathRuns.isEmpty()) return List.of();
        Set<String> claimedEntries = new LinkedHashSet<>();
        if (claimedCandidates != null) {
            for (AuthBypassCandidate candidate : claimedCandidates) {
                if (candidate != null && candidate.entryRef() != null && !candidate.entryRef().isBlank()) {
                    claimedEntries.add(normalizeEntryRef(candidate.entryRef()));
                }
            }
        }
        List<String> refs = selectAuthEvidence(pathRuns, claimedEntries, true);
        // EntryRef formats differ (entry:<id> vs entry:METHOD:/route); fall back to scan-wide signals.
        if (refs.isEmpty() && !claimedEntries.isEmpty()) {
            refs = selectAuthEvidence(pathRuns, Set.of(), false);
        }
        return refs;
    }

    private static List<String> selectAuthEvidence(
            List<ApiDtos.PathRunDto> pathRuns, Set<String> claimedEntries, boolean filterEntries) {
        List<String> refs = new ArrayList<>();
        for (ApiDtos.PathRunDto run : pathRuns) {
            if (run == null || run.pathRunId() == null || run.pathRunId().isBlank()) continue;
            if (filterEntries && !claimedEntries.isEmpty()
                    && !entryMatchesClaim(run.entrypointRef(), claimedEntries)) {
                continue;
            }
            if (isAuthChallenge(run) || isPassGate(run)) {
                refs.add(run.pathRunId());
                if (refs.size() >= 32) break;
            }
        }
        return List.copyOf(refs);
    }

    public static boolean claimsBypassConfirmed(String summaryOrJson, JsonNode modelConfirmation) {
        if (modelConfirmation != null) {
            String status = text(modelConfirmation, "status");
            if ("DYNAMIC_CONTRAST".equalsIgnoreCase(status)) return true;
        }
        if (summaryOrJson == null || summaryOrJson.isBlank()) return false;
        String lower = summaryOrJson.toLowerCase(Locale.ROOT);
        return lower.contains("bypass confirmed")
                || lower.contains("bypass succeeded")
                || lower.contains("auth_bypass_confirmed")
                || lower.contains("已绕过")
                || lower.contains("绕过已确认")
                || lower.contains("绕过成功")
                || lower.contains("确认绕过")
                || lower.contains("\"status\"") && lower.contains("dynamic_contrast");
    }

    private static JsonNode extractBypassConfirmationNode(String summaryOrJson) {
        if (summaryOrJson == null || summaryOrJson.isBlank()) return null;
        try {
            JsonNode root = JSON.readTree(summaryOrJson.trim());
            JsonNode block = root.get("bypassConfirmation");
            if (block != null && block.isObject()) return block;
        } catch (Exception ignored) {
            // Fall through to embedded object scan.
        }
        int idx = indexOfIgnoreCase(summaryOrJson, "\"bypassConfirmation\"");
        if (idx < 0) return null;
        int start = summaryOrJson.indexOf('{', idx);
        if (start < 0) return null;
        String slice = balancedObject(summaryOrJson, start);
        if (slice == null) return null;
        try {
            return JSON.readTree(slice);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static boolean isAuthChallenge(ApiDtos.PathRunDto run) {
        return run != null && "AUTH_CHALLENGE".equalsIgnoreCase(
                run.outcomeClass() == null ? "" : run.outcomeClass());
    }

    private static boolean isPassGate(ApiDtos.PathRunDto run) {
        if (run == null) return false;
        String track = run.track() == null ? "" : run.track().trim().toUpperCase(Locale.ROOT);
        if (!"BYPASS_CANDIDATE".equals(track) && !"ADMIN".equals(track)) return false;
        int status = run.httpStatus();
        return status >= 200 && status < 400;
    }

    private static boolean entryMatchesClaim(String entrypointRef, Set<String> claimedEntries) {
        if (claimedEntries == null || claimedEntries.isEmpty()) return true;
        String normalized = normalizeEntryRef(entrypointRef);
        if (claimedEntries.contains(normalized)) return true;
        // PathRun entry refs are often entry:METHOD:/route while PoCs use entry:<id>.
        for (String claimed : claimedEntries) {
            if (normalized.contains(claimed) || claimed.contains(normalized)) return true;
            String bare = claimed.startsWith("entry:") ? claimed.substring("entry:".length()) : claimed;
            if (!bare.isBlank() && normalized.contains(bare)) return true;
        }
        return false;
    }

    private static String normalizeEntryRef(String entryRef) {
        if (entryRef == null) return "";
        return entryRef.trim().toLowerCase(Locale.ROOT);
    }

    public static ObjectNode toJson(AuthBypassCandidate candidate) {
        ObjectNode node = JSON.createObjectNode();
        node.put("entryRef", candidate.entryRef());
        node.put("techniqueId", candidate.techniqueId());
        node.put("track", candidate.track().name());
        node.put("rationale", candidate.rationale());
        ArrayNode refs = node.putArray("evidenceRefs");
        for (String ref : candidate.evidenceRefs()) refs.add(ref);
        node.put("confidence", candidate.confidence());
        if (candidate.hasAuthMaterial()) {
            node.put("authorizationHeader", candidate.authorizationHeader());
        }
        if (candidate.bladeAuthHeader() != null && !candidate.bladeAuthHeader().isBlank()) {
            node.put("bladeAuthHeader", candidate.bladeAuthHeader());
        }
        if (candidate.query() != null && !candidate.query().isBlank()) {
            node.put("query", candidate.query());
        }
        if (candidate.bodyHint() != null && !candidate.bodyHint().isBlank()) {
            node.put("bodyHint", candidate.bodyHint());
        }
        node.put("hasAuthMaterial", candidate.hasAuthMaterial());
        node.put("classification", "INFERENCE");
        return node;
    }

    public static AuthSurface detectAuthSurface(ApiDtos.ScanDto scan) {
        if (scan == null) {
            return new AuthSurface(false, 0, 0, 0, 0, List.of());
        }
        int jwtSinks = 0;
        int authGapSinks = 0;
        for (ApiDtos.SinkDto sink : scan.sinks()) {
            if (sink == null || sink.category() == null) continue;
            String category = sink.category().trim().toUpperCase(Locale.ROOT);
            if ("JWT".equals(category)) jwtSinks++;
            else if ("AUTH_GAP".equals(category) || "AUTH".equals(category)) authGapSinks++;
        }
        int jwtOrAuthFindings = 0;
        for (ApiDtos.FindingDto finding : scan.findings()) {
            if (finding == null) continue;
            if (looksJwtOrAuthGap(finding.title())
                    || looksJwtOrAuthGap(finding.sink())
                    || looksJwtOrAuthGap(finding.entry())) {
                jwtOrAuthFindings++;
            }
        }
        List<String> authEntries = new ArrayList<>();
        for (ApiDtos.EntryDto entry : scan.entries()) {
            if (entry == null) continue;
            if (!authAnnotations(entry).isEmpty()) {
                authEntries.add("entry:" + entry.id());
            }
        }
        boolean present = jwtSinks > 0 || authGapSinks > 0 || jwtOrAuthFindings > 0
                || !authEntries.isEmpty();
        return new AuthSurface(present, jwtSinks, authGapSinks, jwtOrAuthFindings,
                authEntries.size(),
                authEntries.stream().limit(MAX_SEEDED_ENTRIES).toList());
    }

    /** Empty PoCs are incomplete when the scan exposes an auth surface. */
    public static boolean requiresStructuredBypassPoCs(AuthSurface surface) {
        return surface != null && surface.present();
    }

    public static boolean isIncomplete(List<AuthBypassCandidate> candidates, AuthSurface surface) {
        return requiresStructuredBypassPoCs(surface)
                && (candidates == null || candidates.isEmpty());
    }

    /** Distinct entry+technique(+payload) mechanisms; used for AUTH multi-PoC band. */
    public static int distinctMechanismCount(List<AuthBypassCandidate> candidates) {
        if (candidates == null || candidates.isEmpty()) {
            return 0;
        }
        Set<String> keys = new LinkedHashSet<>();
        for (AuthBypassCandidate candidate : candidates) {
            if (candidate != null) {
                keys.add(key(candidate));
            }
        }
        return keys.size();
    }

    /**
     * Surface present but fewer than {@link #AUTH_POC_MECHANISM_MIN} distinct mechanisms,
     * and model did not supply enough infeasible evidence refs to explain the gap.
     */
    public static boolean isSparseMechanisms(
            List<AuthBypassCandidate> candidates, AuthSurface surface, int infeasibleEvidenceCount) {
        if (!requiresStructuredBypassPoCs(surface)) {
            return false;
        }
        int distinct = distinctMechanismCount(candidates);
        if (distinct >= AUTH_POC_MECHANISM_MIN) {
            return false;
        }
        int covered = distinct + Math.max(0, infeasibleEvidenceCount);
        return covered < AUTH_POC_MECHANISM_MIN;
    }

    public static int countInfeasibleEvidence(String summaryOrJson) {
        if (summaryOrJson == null || summaryOrJson.isBlank()) {
            return 0;
        }
        try {
            JsonNode root = extractJson(summaryOrJson);
            if (root == null || !root.isObject()) {
                return 0;
            }
            JsonNode infeasible = root.get("infeasibleEntries");
            if (infeasible == null || !infeasible.isArray()) {
                infeasible = root.get("infeasibleEvidence");
            }
            if (infeasible == null || !infeasible.isArray()) {
                return 0;
            }
            int count = 0;
            for (JsonNode item : infeasible) {
                if (item == null || item.isNull()) {
                    continue;
                }
                if (item.isTextual() && !item.asText("").isBlank()) {
                    count++;
                } else if (item.isObject()) {
                    String entry = text(item, "entryRef");
                    String reason = text(item, "reason");
                    String evidence = text(item, "evidenceRef");
                    if (!entry.isBlank() && (!reason.isBlank() || !evidence.isBlank())) {
                        count++;
                    }
                }
                if (count >= AUTH_POC_MECHANISM_MIN) {
                    break;
                }
            }
            return count;
        } catch (RuntimeException ignored) {
            return 0;
        }
    }

    /**
     * Prefer auth-material PoCs, then diversify by entryRef/technique for DYNAMIC
     * sandbox_probe attempts (prompt band and server auto-enqueue fallback).
     */
    public static List<AuthBypassCandidate> selectTopProbeTargets(
            List<AuthBypassCandidate> candidates, int limit) {
        if (candidates == null || candidates.isEmpty() || limit <= 0) {
            return List.of();
        }
        int capped = Math.min(DYNAMIC_POC_PROBE_MAX, Math.max(1, limit));
        List<AuthBypassCandidate> withAuth = new ArrayList<>();
        List<AuthBypassCandidate> withoutAuth = new ArrayList<>();
        for (AuthBypassCandidate candidate : candidates) {
            if (candidate == null) continue;
            if (candidate.hasAuthMaterial()) withAuth.add(candidate);
            else withoutAuth.add(candidate);
        }
        List<AuthBypassCandidate> ordered = new ArrayList<>(withAuth.size() + withoutAuth.size());
        ordered.addAll(withAuth);
        ordered.addAll(withoutAuth);
        List<AuthBypassCandidate> selected = new ArrayList<>();
        Set<String> selectedKeys = new LinkedHashSet<>();
        Set<String> selectedEntries = new LinkedHashSet<>();
        // Pass 1: one PoC per entryRef (auth-material first).
        for (AuthBypassCandidate candidate : ordered) {
            if (selected.size() >= capped) break;
            String key = candidate.entryRef() + "|" + candidate.techniqueId();
            if (selectedKeys.contains(key) || selectedEntries.contains(candidate.entryRef())) {
                continue;
            }
            selectedKeys.add(key);
            selectedEntries.add(candidate.entryRef());
            selected.add(candidate);
        }
        // Pass 2: fill remaining slots with unused technique/entry pairs.
        for (AuthBypassCandidate candidate : ordered) {
            if (selected.size() >= capped) break;
            String key = candidate.entryRef() + "|" + candidate.techniqueId();
            if (!selectedKeys.add(key)) continue;
            selected.add(candidate);
        }
        return List.copyOf(selected);
    }

    /**
     * Server draft candidates from static JWT/AUTH_GAP/auth-entry signals.
     * Marked RULE_GENERATED; DYNAMIC may attempt them. Never upgrades verification alone.
     */
    public static List<AuthBypassCandidate> seedRuleGeneratedDrafts(ApiDtos.ScanDto scan) {
        return seedRuleGeneratedDrafts(scan, null);
    }

    /**
     * Server draft candidates from static JWT/AUTH_GAP/auth-entry signals.
     * DEFAULT_SECRET_HS256 is seeded only when harvest found mintable sign-key material
     * in the artifact (low-confidence RULE_GENERATED). Multi-header auth surface alone never
     * forges a commercial default JWT. Secret-less techniques (MISSING_AUTH / EMPTY_BEARER /
     * ALG_NONE) remain available without harvested keys.
     */
    public static List<AuthBypassCandidate> seedRuleGeneratedDrafts(
            ApiDtos.ScanDto scan, java.nio.file.Path artifactPath) {
        if (scan == null) return List.of();
        AuthSurface surface = detectAuthSurface(scan);
        if (!surface.present()) return List.of();
        List<ApiDtos.EntryDto> targets = selectSeedEntries(scan);
        if (targets.isEmpty()) return List.of();
        SyntheticIdentityService identity = new SyntheticIdentityService();
        SyntheticIdentityService.MaterialBundle materials = identity.harvest(artifactPath);
        boolean multiHeaderSurface = materials.multiHeaderAuthSurface()
                || materials.preferSecondaryAuthHeader()
                || looksMultiHeaderAuthScan(scan);
        boolean harvestedSecret = materials.jwtSecret().isPresent();
        SyntheticIdentityService.SyntheticIdentity defaultHs256 =
                identity.synthesizeTechnique(AuthBypassTechnique.DEFAULT_SECRET_HS256, materials);
        SyntheticIdentityService.SyntheticIdentity algNone =
                identity.synthesizeTechnique(AuthBypassTechnique.ALG_NONE, materials);
        SyntheticIdentityService.SyntheticIdentity emptyBearer =
                identity.synthesizeTechnique(AuthBypassTechnique.EMPTY_BEARER, materials);
        List<AuthBypassCandidate> drafts = new ArrayList<>();
        boolean jwtSignal = surface.jwtSinkCount() > 0 || surface.jwtOrAuthGapFindingCount() > 0
                || surface.authGapSinkCount() > 0 || multiHeaderSurface;
        for (ApiDtos.EntryDto entry : targets) {
            if (drafts.size() >= MAX_SEEDED_POCS) break;
            String entryRef = "entry:" + entry.id();
            List<String> refs = entry.evidenceRefs() == null ? List.of() : entry.evidenceRefs();
            drafts.add(AuthBypassCandidate.of(
                    entryRef,
                    AuthBypassTechnique.MISSING_AUTH.name(),
                    IdentityTrack.UNAUTH,
                    "RULE_GENERATED draft: probe without Authorization after JWT/AUTH_GAP/"
                            + "auth-annotated surface; AI omitted structured bypassPoCs",
                    refs, 0.25, "", "", "", ""));
            if (drafts.size() >= MAX_SEEDED_POCS) break;
            if (jwtSignal && harvestedSecret && defaultHs256.available()) {
                String token = defaultHs256.authorizationHeader();
                String secondary = multiHeaderSurface
                        ? SyntheticIdentityService.secondaryAuthHeaderValue(token) : "";
                drafts.add(AuthBypassCandidate.of(
                        entryRef,
                        AuthBypassTechnique.DEFAULT_SECRET_HS256.name(),
                        IdentityTrack.BYPASS_CANDIDATE,
                        "RULE_GENERATED draft: HS256 JWT minted from artifact-harvested sign-key ("
                                + materials.secretProvenance() + "); not a global hardcoded FACT",
                        refs, 0.45,
                        "Bearer " + token,
                        secondary,
                        "", ""));
            } else if (jwtSignal && emptyBearer.available()) {
                drafts.add(AuthBypassCandidate.of(
                        entryRef,
                        AuthBypassTechnique.EMPTY_BEARER.name(),
                        IdentityTrack.BYPASS_CANDIDATE,
                        "RULE_GENERATED draft: empty Bearer hypothesis for JWT/auth surface"
                                + (multiHeaderSurface && !harvestedSecret
                                ? "; multi-header auth surface without harvested sign-key" : ""),
                        refs, 0.28, emptyBearer.authorizationHeader(), "", "", ""));
            }
            if (drafts.size() >= MAX_SEEDED_POCS) break;
            if (jwtSignal && algNone.available() && !(multiHeaderSurface && harvestedSecret)) {
                drafts.add(AuthBypassCandidate.of(
                        entryRef,
                        AuthBypassTechnique.ALG_NONE.name(),
                        IdentityTrack.BYPASS_CANDIDATE,
                        "RULE_GENERATED draft: alg-none JWT hypothesis for DYNAMIC sandbox_probe; "
                                + "refine with AI headers when available",
                        refs, 0.30,
                        "Bearer " + algNone.authorizationHeader(), "", "", ""));
            } else if (jwtSignal && multiHeaderSurface && harvestedSecret && emptyBearer.available()) {
                drafts.add(AuthBypassCandidate.of(
                        entryRef,
                        AuthBypassTechnique.EMPTY_BEARER.name(),
                        IdentityTrack.BYPASS_CANDIDATE,
                        "RULE_GENERATED draft: empty Bearer hypothesis for multi-header JWT surface",
                        refs, 0.28, emptyBearer.authorizationHeader(), "", "", ""));
            }
        }
        return List.copyOf(drafts).stream().limit(AuthBypassCandidate.MAX_CANDIDATES).toList();
    }

    /** True when scan entries suggest an adapter that prefers a secondary auth header. */
    private static boolean looksMultiHeaderAuthScan(ApiDtos.ScanDto scan) {
        if (scan == null || scan.entries() == null) return false;
        List<String> routes = new ArrayList<>();
        for (ApiDtos.EntryDto entry : scan.entries()) {
            if (entry == null) continue;
            if (entry.route() != null && !entry.route().isBlank()) {
                routes.add(entry.route());
            }
        }
        for (com.aq.jvmsentinel.analysis.framework.FrameworkAdapter adapter
                : com.aq.jvmsentinel.analysis.framework.FrameworkAdapterRegistry.matching(null, routes)) {
            if (adapter.preferSecondaryAuthHeader(null)
                    && adapter.secondaryAuthHeaderName() != null
                    && !adapter.secondaryAuthHeaderName().isBlank()) {
                return true;
            }
        }
        return false;
    }

    private static List<ApiDtos.EntryDto> selectSeedEntries(ApiDtos.ScanDto scan) {
        List<ApiDtos.EntryDto> highValue = new ArrayList<>();
        List<ApiDtos.EntryDto> authAnnotated = new ArrayList<>();
        List<ApiDtos.EntryDto> fallback = new ArrayList<>();
        for (ApiDtos.EntryDto entry : scan.entries()) {
            if (entry == null || entry.id() == null || entry.id().isBlank()) continue;
            String route = entry.route() == null ? "" : entry.route().toLowerCase(Locale.ROOT);
            boolean bladeHighValue = route.contains("deploy-upload")
                    || route.contains("/oauth/token")
                    || route.contains("/blade-flow/manager")
                    || route.contains("/blade-flow/model");
            if (bladeHighValue) {
                highValue.add(entry);
            } else if (!authAnnotations(entry).isEmpty()) {
                authAnnotated.add(entry);
            } else if (fallback.size() < MAX_SEEDED_ENTRIES) {
                fallback.add(entry);
            }
        }
        List<ApiDtos.EntryDto> selected = new ArrayList<>();
        for (ApiDtos.EntryDto entry : highValue) {
            if (selected.size() >= MAX_SEEDED_ENTRIES) break;
            selected.add(entry);
        }
        for (ApiDtos.EntryDto entry : authAnnotated) {
            if (selected.size() >= MAX_SEEDED_ENTRIES) break;
            if (!selected.contains(entry)) selected.add(entry);
        }
        if (!selected.isEmpty()) {
            return List.copyOf(selected);
        }
        return fallback.stream().limit(MAX_SEEDED_ENTRIES).toList();
    }

    private static List<String> authAnnotations(ApiDtos.EntryDto entry) {
        if (entry == null || entry.preconditions() == null) return List.of();
        List<String> matched = new ArrayList<>();
        for (String precondition : entry.preconditions()) {
            if (looksAuthRelated(precondition)) matched.add(precondition);
        }
        return matched;
    }

    private static boolean looksJwtOrAuthGap(String value) {
        if (value == null || value.isBlank()) return false;
        String normalized = value.toLowerCase(Locale.ROOT);
        return normalized.contains("jwt")
                || normalized.contains("auth_gap")
                || normalized.contains("auth-gap")
                || normalized.contains("鉴权缺口")
                || normalized.contains("令牌");
    }

    private static boolean looksAuthRelated(String value) {
        if (value == null) return false;
        String normalized = value.toLowerCase(Locale.ROOT);
        return normalized.contains("auth")
                || normalized.contains("role")
                || normalized.contains("permit")
                || normalized.contains("security")
                || normalized.contains("preauthorize")
                || normalized.contains("secured")
                || normalized.contains("anonymous")
                || normalized.contains("jwt")
                || normalized.contains("token")
                || normalized.contains("权限")
                || normalized.contains("鉴权")
                || normalized.contains("认证")
                || normalized.contains("角色");
    }

    public static List<AuthBypassCandidate> fromConclusionJson(String conclusionJson) {
        if (conclusionJson == null || conclusionJson.isBlank()) return List.of();
        try {
            JsonNode root = JSON.readTree(conclusionJson);
            JsonNode array = root.get("bypassPoCs");
            if (array == null || !array.isArray()) array = root.get("bypassCandidates");
            if (array == null || !array.isArray()) return List.of();
            List<AuthBypassCandidate> result = new ArrayList<>();
            for (JsonNode item : array) {
                try {
                    result.add(fromNode(item, null));
                } catch (IllegalArgumentException ignored) {
                    // Drop corrupted persisted rows fail-closed.
                }
            }
            return List.copyOf(result);
        } catch (Exception ignored) {
            return List.of();
        }
    }

    public static String emptyReasonFromConclusion(String conclusionJson) {
        if (conclusionJson == null || conclusionJson.isBlank()) return "";
        try {
            return text(JSON.readTree(conclusionJson), "emptyReason");
        } catch (Exception ignored) {
            return "";
        }
    }

    private static AuthBypassCandidate fromNode(JsonNode item, Set<String> allowedEntryRefs) {
        if (item == null || !item.isObject()) {
            throw new IllegalArgumentException("PoC must be object");
        }
        String entryRef = text(item, "entryRef");
        if (entryRef.isBlank()) entryRef = text(item, "entrypointRef");
        String techniqueId = text(item, "techniqueId");
        if (techniqueId.isBlank()) techniqueId = "CUSTOM_POC";
        IdentityTrack track = resolveTrack(techniqueId, text(item, "track"));
        List<String> refs = new ArrayList<>();
        JsonNode evidence = item.get("evidenceRefs");
        if (evidence != null && evidence.isArray()) {
            for (JsonNode ref : evidence) refs.add(ref.asText());
        }
        double confidence = item.path("confidence").isNumber()
                ? item.path("confidence").asDouble(0.3) : 0.3;
        String authorization = firstNonBlank(
                text(item, "authorizationHeader"),
                text(item, "authorization"),
                text(item, "jwt"),
                text(item, "token"));
        String secondary = firstNonBlank(
                text(item, "secondaryAuthorizationHeader"),
                text(item, "secondaryAuthHeader"),
                text(item, "bladeAuthHeader"),
                text(item, "bladeAuth"));
        AuthBypassCandidate candidate = AuthBypassCandidate.of(
                entryRef, techniqueId, track, text(item, "rationale"), refs, confidence,
                authorization, secondary, text(item, "query"),
                firstNonBlank(text(item, "bodyHint"), text(item, "body")));
        requireAllowedEntry(candidate.entryRef(), allowedEntryRefs);
        return candidate;
    }

    private static IdentityTrack resolveTrack(String techniqueId, String trackName) {
        if (trackName != null && !trackName.isBlank()) {
            try {
                return IdentityTrack.valueOf(trackName.trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException invalid) {
                throw new IllegalArgumentException("track is invalid");
            }
        }
        return AuthBypassTechnique.tryParse(techniqueId)
                .map(AuthBypassTechnique::defaultTrack)
                .orElse(IdentityTrack.BYPASS_CANDIDATE);
    }

    private static void requireAllowedEntry(String entryRef, Set<String> allowedEntryRefs) {
        if (allowedEntryRefs == null) return;
        if (!allowedEntryRefs.contains(entryRef)) {
            throw new IllegalArgumentException("ENTRYPOINT_NOT_FOUND:" + entryRef);
        }
    }

    private static JsonNode extractJson(String text) {
        if (text == null || text.isBlank()) return null;
        String trimmed = text.trim();
        try {
            JsonNode direct = JSON.readTree(trimmed);
            if (direct.has("bypassPoCs") || direct.has("bypassCandidates")) return direct;
        } catch (Exception ignored) {
            // Fall through.
        }
        Matcher fenced = FENCED_JSON.matcher(trimmed);
        if (fenced.find()) {
            try {
                return JSON.readTree(fenced.group(1));
            } catch (Exception ignored) {
                // continue
            }
        }
        int idx = indexOfIgnoreCase(trimmed, "\"bypassPoCs\"");
        if (idx < 0) idx = indexOfIgnoreCase(trimmed, "\"bypassCandidates\"");
        if (idx >= 0) {
            int start = trimmed.lastIndexOf('{', idx);
            if (start >= 0) {
                String slice = balancedObject(trimmed, start);
                if (slice != null) {
                    try {
                        return JSON.readTree(slice);
                    } catch (Exception ignored) {
                        // continue
                    }
                }
            }
        }
        return null;
    }

    private static int indexOfIgnoreCase(String haystack, String needle) {
        return haystack.toLowerCase(Locale.ROOT).indexOf(needle.toLowerCase(Locale.ROOT));
    }

    private static String balancedObject(String text, int start) {
        int depth = 0;
        boolean inString = false;
        boolean escape = false;
        for (int i = start; i < text.length(); i++) {
            char c = text.charAt(i);
            if (inString) {
                if (escape) escape = false;
                else if (c == '\\') escape = true;
                else if (c == '"') inString = false;
                continue;
            }
            if (c == '"') inString = true;
            else if (c == '{') depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0) return text.substring(start, i + 1);
            }
        }
        return null;
    }

    private static String text(JsonNode node, String field) {
        if (node == null || field == null) return "";
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? "" : Objects.toString(value.asText(""), "").trim();
    }

    private static String firstNonBlank(String... values) {
        if (values == null) return "";
        for (String value : values) {
            if (value != null && !value.isBlank()) return value;
        }
        return "";
    }

    private static String key(AuthBypassCandidate candidate) {
        return candidate.entryRef() + "|" + candidate.techniqueId() + "|" + candidate.track().name()
                + "|" + Integer.toHexString(Objects.hash(
                candidate.authorizationHeader(), candidate.bladeAuthHeader(),
                candidate.query(), candidate.bodyHint()));
    }
}

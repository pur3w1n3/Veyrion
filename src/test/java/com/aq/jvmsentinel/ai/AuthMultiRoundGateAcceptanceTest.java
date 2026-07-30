package com.aq.jvmsentinel.ai;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.model.IdentityTrack;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P0-04：AUTH code_query / 多 PoC 多样化 / authPass 身份闸门（纯单元切片）。
 */
public final class AuthMultiRoundGateAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        duplicatePayloadVariantsAreDeduped();
        sparseMechanismsRequireRepairUnlessInfeasibleEvidence();
        authPassConstantsAreExplicit();
        System.out.println("AuthMultiRoundGateAcceptanceTest: PASS ("
                + ASSERTIONS.get() + " assertions)");
    }

    private static void duplicatePayloadVariantsAreDeduped() {
        String summary = """
                {"bypassPoCs":[
                  {"entryRef":"entry:a","techniqueId":"ALG_NONE","track":"BYPASS_CANDIDATE",
                   "rationale":"r1","confidence":0.5,"authorizationHeader":"eyJhbGciOiJub25lIn0.e30."},
                  {"entryRef":"entry:a","techniqueId":"ALG_NONE","track":"BYPASS_CANDIDATE",
                   "rationale":"r2 duplicate payload","confidence":0.6,"authorizationHeader":"eyJhbGciOiJub25lIn0.e30."},
                  {"entryRef":"entry:a","techniqueId":"MISSING_AUTH","track":"UNAUTH",
                   "rationale":"r3","confidence":0.4}
                ]}
                """;
        AuthBypassFeasibility.ParseResult parsed =
                AuthBypassFeasibility.parseAndValidate(summary, null);
        check(parsed.candidates().size() == 2, "duplicate payload variant rejected");
        check(parsed.rejected().stream().anyMatch(item -> item.startsWith("DUPLICATE:")),
                "duplicate rejected with DUPLICATE code");
        check(AuthBypassFeasibility.distinctMechanismCount(parsed.candidates()) == 2,
                "distinct mechanism count excludes duplicates");
    }

    private static void sparseMechanismsRequireRepairUnlessInfeasibleEvidence() {
        AuthBypassFeasibility.AuthSurface surface = new AuthBypassFeasibility.AuthSurface(
                true, 1, 1, 1, 1, List.of("entry:a"));
        List<AuthBypassCandidate> one = List.of(AuthBypassCandidate.of(
                "entry:a", "ALG_NONE", IdentityTrack.BYPASS_CANDIDATE,
                "only one", List.of("evidence:a"), 0.5,
                "eyJhbGciOiJub25lIn0.e30.", "", "", ""));
        check(AuthBypassFeasibility.isSparseMechanisms(one, surface, 0),
                "single PoC is sparse on auth surface");
        check(!AuthBypassFeasibility.isSparseMechanisms(one, surface, 2),
                "infeasible evidence can cover the diversity gap");
        String withInfeasible = """
                {"bypassPoCs":[{"entryRef":"entry:a","techniqueId":"ALG_NONE","track":"BYPASS_CANDIDATE",
                "rationale":"r","confidence":0.5,"authorizationHeader":"eyJhbGciOiJub25lIn0.e30."}],
                "infeasibleEntries":[
                  {"entryRef":"entry:b","reason":"no session path","evidenceRef":"code:session"},
                  {"entryRef":"entry:c","reason":"api key unused","evidenceRef":"code:key"}
                ]}
                """;
        check(AuthBypassFeasibility.countInfeasibleEvidence(withInfeasible) == 2,
                "infeasibleEntries counted");
        AuthBypassFeasibility.ParseResult parsed =
                AuthBypassFeasibility.parseAndValidate(withInfeasible, null);
        check(!AuthBypassFeasibility.isSparseMechanisms(parsed.candidates(), surface,
                        AuthBypassFeasibility.countInfeasibleEvidence(withInfeasible)),
                "1 PoC + 2 infeasible is not sparse");
    }

    private static void authPassConstantsAreExplicit() {
        check(AuthBypassFeasibility.AUTH_PASS_INITIAL.equals("AUTH_INITIAL"),
                "initial AUTH pass identity");
        check(AuthBypassFeasibility.AUTH_PASS_CONFIRM.equals("AUTH_BYPASS_CONFIRM"),
                "confirm AUTH pass identity");
        check(AuthBypassFeasibility.CODE_QUERY_REQUIRED.equals("AUTH_CODE_QUERY_REQUIRED"),
                "code_query gate code");
        // 触及 ApiDtos schema 常量以保持 finding/report 消费者对齐。
        check(ApiDtos.SCHEMA_VERSION >= 1, "API schema version present");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

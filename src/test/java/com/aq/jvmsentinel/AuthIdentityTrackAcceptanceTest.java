package com.aq.jvmsentinel;

import com.aq.jvmsentinel.ai.AuthBypassFeasibility;
import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.service.ProbePlanService;
import com.aq.jvmsentinel.model.AuthBypassTechnique;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.model.PathOutcomeClass;
import com.aq.jvmsentinel.model.PathOutcomeClassifier;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P1-21: AUTH identity-track fail-closed contrasts for MISSING_AUTH, empty Bearer,
 * ALG_NONE, IDENTITY_UNAVAILABLE, and AUTH_CONFIRM hypothesis/contrast/insufficient
 * three-state (fixture; not live Docker production orchestration).
 */
public final class AuthIdentityTrackAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        missingAuthUnauthenticatedContrast();
        emptyBearerDistinctFromMissingAuth();
        algNoneUnsignedJwtWithoutHarvest();
        identityUnavailableDoesNotForgeEmptyToken();
        authChallengeVersusPassGateOutcomes();
        authConfirmHypothesisContrastInsufficientThreeState();
        System.out.println("AuthIdentityTrackAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void missingAuthUnauthenticatedContrast() {
        ProbePlanService.AuthMaterialized omitted =
                ProbePlanService.materializeAiPocAuth("MISSING_AUTH", null, null, null);
        check(omitted.track() == IdentityTrack.UNAUTH, "MISSING_AUTH track=UNAUTH");
        check(omitted.authToken().isEmpty() && omitted.secondaryAuthToken().isEmpty(),
                "MISSING_AUTH omits both auth channels");
        check(omitted.identityAvailable(), "MISSING_AUTH remains an intentional probe");
        check("MISSING_AUTH".equals(omitted.provenance()), "MISSING_AUTH provenance");

        ProbePlanService.AuthMaterialized emptyHeader =
                ProbePlanService.materializeAiPocAuth("MISSING_AUTH", "", "", null);
        check(emptyHeader.authToken().isEmpty() && emptyHeader.identityAvailable(),
                "empty Authorization still means unauthenticated MISSING_AUTH");

        try {
            ProbePlanService.materializeAiPocAuth(
                    "MISSING_AUTH", "Bearer eyJhbGciOiJub25lIn0.e30.", null, null);
            throw new AssertionError("MISSING_AUTH must reject forged bearer");
        } catch (IllegalArgumentException expected) {
            check("MISSING_AUTH_MUST_OMIT_AUTHORIZATION".equals(expected.getMessage()),
                    "stable MISSING_AUTH rejection code");
        }
    }

    private static void emptyBearerDistinctFromMissingAuth() {
        ProbePlanService.AuthMaterialized emptyBearer =
                ProbePlanService.materializeAiPocAuth("EMPTY_BEARER", null, null, null);
        check(emptyBearer.track() == IdentityTrack.BYPASS_CANDIDATE,
                "EMPTY_BEARER uses bypass candidate track");
        check(emptyBearer.identityAvailable(), "EMPTY_BEARER is available without harvest");
        check(emptyBearer.authToken() != null && !emptyBearer.authToken().isEmpty(),
                "EMPTY_BEARER supplies blank-ish bearer material");
        check(emptyBearer.secondaryAuthToken().isEmpty(),
                "EMPTY_BEARER does not invent secondary auth");
        check(!emptyBearer.provenance().contains("IDENTITY_UNAVAILABLE"),
                "EMPTY_BEARER is not IDENTITY_UNAVAILABLE");

        // AI-authored empty bearer literal must stay on bypass track, not collapse to MISSING_AUTH.
        ProbePlanService.AuthMaterialized aiEmpty =
                ProbePlanService.materializeAiPocAuth("EMPTY_BEARER", "Bearer ", null, null);
        check(aiEmpty.track() == IdentityTrack.BYPASS_CANDIDATE,
                "AI empty Bearer stays BYPASS_CANDIDATE");
        check(aiEmpty.identityAvailable(), "AI empty Bearer remains probeable");
    }

    private static void algNoneUnsignedJwtWithoutHarvest() {
        ProbePlanService.AuthMaterialized algNone =
                ProbePlanService.materializeAiPocAuth("ALG_NONE", null, null, null);
        check(algNone.identityAvailable(), "ALG_NONE available without signing material");
        check(algNone.track() == IdentityTrack.BYPASS_CANDIDATE, "ALG_NONE track");
        check(algNone.authToken().contains("."), "ALG_NONE mints JWT-shaped token");
        check(algNone.authToken().startsWith("eyJ")
                        || "RULE_GENERATED".equals(algNone.provenance()),
                "ALG_NONE uses unsigned JWT material (RULE_GENERATED)");
        check(algNone.secondaryAuthToken().isEmpty(), "ALG_NONE leaves secondary channel empty");

        ProbePlanService.AuthMaterialized aiAlg = ProbePlanService.materializeAiPocAuth(
                "ALG_NONE", "Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.", null, null);
        check(aiAlg.identityAvailable() && !aiAlg.authToken().isBlank(),
                "ALG_NONE accepts AI-authored unsigned JWT");
    }

    private static void identityUnavailableDoesNotForgeEmptyToken() {
        ProbePlanService.AuthMaterialized noSecret =
                ProbePlanService.materializeAiPocAuth("DEFAULT_SECRET_HS256", null, null, null);
        check(!noSecret.identityAvailable(), "DEFAULT_SECRET without harvest unavailable");
        check(noSecret.authToken().isBlank() && noSecret.secondaryAuthToken().isBlank(),
                "unavailable must not forge empty bearer");
        check(noSecret.provenance() != null
                        && noSecret.provenance().contains("IDENTITY_UNAVAILABLE"),
                "provenance marks IDENTITY_UNAVAILABLE");

        SyntheticIdentityService.SyntheticIdentity roleConfusion =
                new SyntheticIdentityService().synthesizeTechnique(
                        AuthBypassTechnique.ROLE_CONFUSION,
                        new SyntheticIdentityService.MaterialBundle(
                                java.util.Optional.empty(), "NONE", java.util.List.of(),
                                false, false, ""));
        check(!roleConfusion.available(), "ROLE_CONFUSION without key unavailable");
        check(roleConfusion.authorizationHeader() == null
                        || roleConfusion.authorizationHeader().isBlank(),
                "ROLE_CONFUSION unavailable has no forged token");
        check(roleConfusion.precondition().contains("IDENTITY_UNAVAILABLE"),
                "ROLE_CONFUSION precondition names IDENTITY_UNAVAILABLE");
    }

    private static void authChallengeVersusPassGateOutcomes() {
        check(PathOutcomeClassifier.classify(401, "", "WWW-Authenticate")
                        == PathOutcomeClass.AUTH_CHALLENGE,
                "401 → AUTH_CHALLENGE for MISSING_AUTH contrast");
        check(PathOutcomeClassifier.classify(403, "", "forbidden")
                        == PathOutcomeClass.AUTH_CHALLENGE,
                "403 → AUTH_CHALLENGE");
        check(PathOutcomeClassifier.classify(200, "", "ok")
                        == PathOutcomeClass.HTTP_OBSERVED,
                "2xx pass-gate → HTTP_OBSERVED");
        check(PathOutcomeClass.IDENTITY_UNAVAILABLE.name().equals("IDENTITY_UNAVAILABLE"),
                "IDENTITY_UNAVAILABLE remains a first-class outcome code");
        // AUTH_CONFIRM distinction: challenge alone never upgrades verification.
        check(PathOutcomeClassifier.classify(401, "", "unauthorized")
                        != PathOutcomeClass.HTTP_OBSERVED,
                "challenge must not be misclassified as pass-gate");
        check(AuthBypassFeasibility.AUTH_PASS_CONFIRM.equals("AUTH_BYPASS_CONFIRM"),
                "AUTH_CONFIRM pass constant is AUTH_BYPASS_CONFIRM");
        check(!AuthBypassFeasibility.AUTH_PASS_INITIAL.equals(AuthBypassFeasibility.AUTH_PASS_CONFIRM),
                "AUTH_CONFIRM distinct from AUTH_INITIAL");
    }

    /**
     * AUTH_CONFIRM three-state: HYPOTHESIS / DYNAMIC_CONTRAST / INSUFFICIENT_EVIDENCE.
     * Fixture-only; never elevates to VERIFIED.
     */
    private static void authConfirmHypothesisContrastInsufficientThreeState() {
        AuthBypassFeasibility.BypassConfirmation hypothesis =
                AuthBypassFeasibility.evaluateBypassConfirmation(
                        "{\"summary\":\"candidate only\"}", List.of(), List.of());
        check(hypothesis.status()
                        == AuthBypassFeasibility.BypassConfirmationStatus.HYPOTHESIS,
                "no claim + no PathRun → HYPOTHESIS");

        AuthBypassFeasibility.BypassConfirmation insufficient =
                AuthBypassFeasibility.evaluateBypassConfirmation(
                        "{\"bypassConfirmation\":{\"status\":\"DYNAMIC_CONTRAST\"},"
                                + "\"summary\":\"confirmed\"}",
                        List.of(), List.of());
        check(insufficient.status()
                        == AuthBypassFeasibility.BypassConfirmationStatus.INSUFFICIENT_EVIDENCE,
                "claimed contrast without PathRun evidence → INSUFFICIENT_EVIDENCE");
        check(insufficient.pathRunRefs().isEmpty(),
                "insufficient evidence carries empty pathRunRefs");

        ApiDtos.PathRunDto contrastRun = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION, "pr-auth-1", "scan-auth", "entry:GET:/api/admin",
                "BYPASS_CANDIDATE", "att-1", "plan-1", "GET", "application/json",
                "GET /api/admin", "AUTH_CHALLENGE", 401,
                true, false, List.of(), "AUTH_CHALLENGE", ApiDtos.DYNAMIC_SUSPECTED,
                List.of("ev-auth-run-1"), ApiDtos.MOCK, "");
        AuthBypassFeasibility.BypassConfirmation contrast =
                AuthBypassFeasibility.evaluateBypassConfirmation(
                        "{\"bypassConfirmation\":{\"status\":\"DYNAMIC_CONTRAST\"},"
                                + "\"summary\":\"AUTH_BYPASS_CONFIRMED\"}",
                        List.of(contrastRun), List.of());
        check(contrast.status()
                        == AuthBypassFeasibility.BypassConfirmationStatus.DYNAMIC_CONTRAST,
                "claimed contrast with PathRun AUTH evidence → DYNAMIC_CONTRAST");
        check(contrast.pathRunRefs().contains("pr-auth-1"),
                "DYNAMIC_CONTRAST carries pathRun refs");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

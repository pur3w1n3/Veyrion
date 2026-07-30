package com.aq.jvmsentinel.analysis.pack;

import com.aq.jvmsentinel.analysis.identity.AuthCodeQueryService;
import com.aq.jvmsentinel.model.ExperimentPlan;
import com.aq.jvmsentinel.model.IdentityTrack;

import java.util.List;

/**
 * P1-02：可选 multi-header JWT + Flowable deploy AnalysisPack shape
 * (non-destructive templates only; not a first-class Blade product path).
 */
public final class AnalysisPackAcceptanceTest {
    public static void main(String[] args) {
        optionalJwtPackMatchesAndSuggestsSecret();
        flowablePackIsMultipartNonDestructive();
        registryMatchingIsRouteDriven();
        System.out.println("AnalysisPackAcceptanceTest: PASS");
    }

    private static void optionalJwtPackMatchesAndSuggestsSecret() {
        BladeJwtCredentialPack pack = new BladeJwtCredentialPack();
        check(pack.matches(null, List.of("/blade-auth/oauth/token")),
                "optional pack matches multi-header auth routes");
        check(!pack.matches(null, List.of("/api/orders")), "pack ignores unrelated routes");
        check(pack.suggestJwtSecret(null).isEmpty(),
                "pack does not invent JWT secrets without artifact harvest");
        check(BladeJwtCredentialPack.DEFAULT_SECRET.equals(
                        AuthCodeQueryService.WELL_KNOWN_BLADE_COMMERCIAL_SIGN_KEY),
                "detection dictionary alias documented for harvest matching only");
        List<ExperimentPlan> templates = pack.experimentTemplates("entry:e1", IdentityTrack.ADMIN);
        check(!templates.isEmpty(), "JWT templates non-empty");
        check(templates.get(0).authRequired(), "ADMIN JWT template authRequired");
        check(!"multipart/form-data".equalsIgnoreCase(templates.get(0).contentType()),
                "JWT templates are not multipart deploy");
    }

    private static void flowablePackIsMultipartNonDestructive() {
        FlowableDeployExperimentPack pack = new FlowableDeployExperimentPack();
        check(pack.matches(null, List.of("/repository/deployments")), "flowable matches deploy route");
        check(pack.matches(null, List.of("/flowable/process-definition")), "flowable matches process-definition");
        List<ExperimentPlan> templates = pack.experimentTemplates("entry:deploy-1", IdentityTrack.UNAUTH);
        check(!templates.isEmpty(), "flowable templates non-empty");
        ExperimentPlan plan = templates.get(0);
        check("multipart/form-data".equalsIgnoreCase(plan.contentType()), "flowable contentType multipart");
        check(plan.requiredParameters().contains("file"), "flowable requires file param");
        check(plan.maxAttempts() <= 2, "flowable attempts bounded");
        String blob = (plan.successHttpHint() + " " + String.join(" ", plan.requiredParameters())).toLowerCase();
        check(!blob.contains("memshell") && !blob.contains("runtime.exec"),
                "flowable template must stay non-destructive");
        check(pack.suggestJwtSecret(null).isEmpty(), "flowable does not invent JWT secrets");
    }

    private static void registryMatchingIsRouteDriven() {
        List<AnalysisPack> matched = AnalysisPackRegistry.matching(null, List.of(
                "/blade-system/user/list", "/repository/deployments"));
        check(matched.stream().anyMatch(pack -> "blade-jwt-default".equals(pack.id())),
                "registry matches blade pack");
        check(matched.stream().anyMatch(pack -> "flowable-deploy-multipart".equals(pack.id())),
                "registry matches flowable pack");
        check(AnalysisPackRegistry.all().size() >= 2, "registry exposes both packs");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

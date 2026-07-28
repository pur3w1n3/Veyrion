package com.aq.jvmsentinel.analysis.detector;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.hypothesis.HypothesisLifecycle;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Heuristic IDOR/BOLA ownership gap: object-id PathVariable/RequestParam on an HTTP
 * entry without ownership / tenant / principal-binding preconditions.
 */
public final class OwnershipIdorDetector implements Detector {
    public static final String VERSION = "0.1.0";
    public static final String PROPERTY = "IDOR_OWNERSHIP_GAP";

    private static final Pattern OBJECT_ID_NAME = Pattern.compile(
            "(?i)^(id|userid|user_id|accountid|orderid|order_id|resourceid|tenantid|ownerid)$");
    private static final Pattern ROUTE_ID = Pattern.compile(
            "(?i)\\{(id|userid|user_id|accountid|orderid|resourceid|ownerid)\\}");
    private static final Pattern OWNERSHIP_GUARD = Pattern.compile(
            "(?i)(authentication\\.|principal|#userid|#user|#account|#owner|tenant|ownership|belongs|"
                    + "sameuser|currentuser|haspermission)");

    @Override
    public String id() {
        return DetectorIds.OWNERSHIP_IDOR;
    }

    @Override
    public String version() {
        return VERSION;
    }

    @Override
    public HypothesisFamily family() {
        return HypothesisFamily.GUARD_COVERAGE;
    }

    @Override
    public List<SecurityHypothesis> analyze(DetectorContext context) {
        List<SecurityHypothesis> out = new ArrayList<>();
        int ordinal = 0;
        for (ApiDtos.EntryDto entry : context.entries()) {
            if (entry == null || !"HTTP".equalsIgnoreCase(entry.protocol())) continue;
            if (hasOwnershipGuard(entry)) continue;
            String objectParam = firstObjectIdParameter(entry);
            if (objectParam == null) continue;
            String route = entry.route() == null ? "" : entry.route();
            String subject = (entry.declaringClass() == null ? "entry" : entry.declaringClass())
                    + " " + entry.method() + " " + route;
            out.add(new SecurityHypothesis(
                    SecurityHypothesis.SCHEMA_VERSION,
                    "hyp-idor-" + context.scanId() + "-" + (++ordinal),
                    context.scanId(),
                    PROPERTY,
                    HypothesisFamily.GUARD_COVERAGE,
                    HypothesisLifecycle.CANDIDATE,
                    id() + "/" + version(),
                    entry.evidenceRefs(),
                    List.of(),
                    List.of(),
                    subject,
                    "object-id:" + objectParam
            ));
        }
        return List.copyOf(out);
    }

    private static String firstObjectIdParameter(ApiDtos.EntryDto entry) {
        for (String parameter : entry.parameters()) {
            if (parameter == null || parameter.isBlank()) continue;
            String lower = parameter.toLowerCase(Locale.ROOT);
            String name = parameterName(parameter);
            boolean binding = lower.contains("kind=pathvariable")
                    || lower.contains("kind=requestparam")
                    || routeHasPathVar(entry.route(), name);
            if (!binding) continue;
            if (OBJECT_ID_NAME.matcher(name).matches()) {
                return name;
            }
        }
        Matcher matcher = ROUTE_ID.matcher(entry.route() == null ? "" : entry.route());
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private static boolean hasOwnershipGuard(ApiDtos.EntryDto entry) {
        for (String precondition : entry.preconditions()) {
            if (precondition == null || precondition.isBlank()) continue;
            if (OWNERSHIP_GUARD.matcher(precondition).find()) {
                return true;
            }
            String lower = precondition.toLowerCase(Locale.ROOT);
            if (lower.startsWith("tenant=")) {
                return true;
            }
        }
        return false;
    }

    private static String parameterName(String encoded) {
        int idx = encoded.toLowerCase(Locale.ROOT).indexOf("name=");
        if (idx < 0) return encoded.trim();
        String rest = encoded.substring(idx + 5).trim();
        int comma = rest.indexOf(',');
        return comma < 0 ? rest : rest.substring(0, comma).trim();
    }

    private static boolean routeHasPathVar(String route, String name) {
        if (route == null || name == null || name.isBlank()) return false;
        return route.toLowerCase(Locale.ROOT).contains("{" + name.toLowerCase(Locale.ROOT) + "}");
    }
}

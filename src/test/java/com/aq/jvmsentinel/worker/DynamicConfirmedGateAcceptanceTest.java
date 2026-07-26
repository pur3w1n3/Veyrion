package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.model.PathOutcomeClass;
import com.aq.jvmsentinel.model.PathRun;
import com.aq.jvmsentinel.model.SqlEvent;
import com.aq.jvmsentinel.model.VerificationStatus;

import java.util.List;

/** Server-only H3 gate must not be model-authoritative. */
public final class DynamicConfirmedGateAcceptanceTest {
    public static void main(String[] args) {
        PathRun parameterized = run(new SqlEvent(
                "select * from t where id=?", "jdbc-placeholders", "READ", true, false, "MOCK"));
        check(DynamicConfirmedGate.evaluate(parameterized, "'\"veyrion-sqli-meta")
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "parameterized SQL must not confirm");

        PathRun injected = run(new SqlEvent(
                "select * from t where id=''\"veyrion-sqli-meta", "", "READ", false, true, "MOCK"));
        check(DynamicConfirmedGate.evaluate(injected, "'\"veyrion-sqli-meta")
                        == VerificationStatus.DYNAMIC_CONFIRMED,
                "unfiltered malicious fragment confirms");

        PathRun applied = DynamicConfirmedGate.apply(injected, "'\"veyrion-sqli-meta");
        check(VerificationStatus.DYNAMIC_CONFIRMED.name().equals(applied.verificationStatus()),
                "apply upgrades PathRun status");
        System.out.println("DynamicConfirmedGateAcceptanceTest passed");
    }

    private static PathRun run(SqlEvent sql) {
        return new PathRun(
                "pr-1", "scan-1", "entry:GET:/x", IdentityTrack.UNAUTH, "attempt-1", null,
                "GET", "application/json", "GET /x", PathOutcomeClass.HTTP_OBSERVED, 200,
                true, true, List.of(sql), "COMPLETED", "DYNAMIC_SUSPECTED", List.of(),
                "MOCK", "no credentials");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

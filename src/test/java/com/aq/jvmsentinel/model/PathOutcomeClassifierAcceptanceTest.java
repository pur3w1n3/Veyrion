package com.aq.jvmsentinel.model;

import com.aq.jvmsentinel.control.ApiDtos;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

/** Focused checks for PathRun outcome taxonomy and track wire round-trip. */
public final class PathOutcomeClassifierAcceptanceTest {
    public static void main(String[] args) throws Exception {
        check(PathOutcomeClassifier.classify(-1, "java.net.SocketTimeoutException", "Read timed out")
                        == PathOutcomeClass.BUSINESS_TIMEOUT,
                "SocketTimeoutException must mean BUSINESS_TIMEOUT after app readiness");
        check(PathOutcomeClassifier.classify(-1, "java.net.ConnectException", "Connection refused")
                        == PathOutcomeClass.COLD_START,
                "ConnectException must mean COLD_START");
        check(PathOutcomeClassifier.classify(401, "", "") == PathOutcomeClass.AUTH_CHALLENGE,
                "401 must mean AUTH_CHALLENGE");

        ObjectMapper mapper = new ObjectMapper();
        ApiDtos.PathRunDto original = new ApiDtos.PathRunDto(
                ApiDtos.SCHEMA_VERSION,
                "pathrun-test",
                "scan-test",
                "entry:GET:/admin",
                IdentityTrack.ADMIN.name(),
                "attempt-1",
                null,
                "GET",
                "application/json",
                "GET /admin track=ADMIN",
                PathOutcomeClass.AUTH_CHALLENGE.name(),
                401,
                true,
                null,
                List.of(),
                PathOutcomeClass.AUTH_CHALLENGE.name(),
                ApiDtos.DYNAMIC_SUSPECTED,
                List.of("evidence-http"),
                ApiDtos.MOCK,
                "synthetic ADMIN JWT");
        ApiDtos.PathRunDto restored = mapper.readValue(mapper.writeValueAsBytes(original), ApiDtos.PathRunDto.class);
        check(IdentityTrack.ADMIN.name().equals(restored.track()), "PathRun track must round-trip");
        check(PathOutcomeClass.AUTH_CHALLENGE.name().equals(restored.outcomeClass()),
                "PathRun outcomeClass must round-trip");

        System.out.println("PathOutcomeClassifierAcceptanceTest: PASS");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

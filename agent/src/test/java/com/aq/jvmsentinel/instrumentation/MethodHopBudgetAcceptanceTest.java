package com.aq.jvmsentinel.instrumentation;

/**
 * XSS / CGLIB METHOD_HOP flood must be dropped so FORCED PathTraces keep business hops.
 */
public final class MethodHopBudgetAcceptanceTest {
    public static void main(String[] args) {
        check(!AgentRuntime.shouldRecordMethodHop(
                        "com.kalvin.kvf.common.xss.HTMLFilter", "filter"),
                "HTMLFilter hops dropped");
        check(!AgentRuntime.shouldRecordMethodHop(
                        "com.kalvin.kvf.common.xss.XssHttpRequestWrapper", "getParameter"),
                "XssHttpRequestWrapper hops dropped");
        check(!AgentRuntime.shouldRecordMethodHop(
                        "com.kalvin.kvf.common.xss.XssFilter", "doFilter"),
                "XssFilter MethodHop dropped (FilterAdvice still observes)");
        check(!AgentRuntime.shouldRecordMethodHop(
                        "com.example.Foo$$EnhancerBySpringCGLIB$$abc", "getBean"),
                "CGLIB enhancer hops dropped");
        check(!AgentRuntime.shouldRecordMethodHop(
                        "com.example.Foo$$FastClassBySpringCGLIB$$abc", "getIndex"),
                "CGLIB FastClass hops dropped");

        AgentRuntime.bindRequestCorrelation("req-test-1");
        try {
            int accepted = 0;
            for (int i = 0; i < AgentRuntime.MAX_METHOD_HOPS_PER_REQUEST + 20; i++) {
                if (AgentRuntime.shouldRecordMethodHop(
                        "com.kalvin.kvf.modules.sys.controller.UserController", "list")) {
                    accepted++;
                }
            }
            check(accepted == AgentRuntime.MAX_METHOD_HOPS_PER_REQUEST,
                    "per-request METHOD_HOP cap enforced; accepted=" + accepted);
            check(!AgentRuntime.shouldRecordMethodHop(
                            "com.kalvin.kvf.modules.sys.service.UserService", "find"),
                    "hops rejected after cap");
        } finally {
            AgentRuntime.releaseRequestCorrelation();
        }

        AgentRuntime.bindRequestCorrelation("req-test-2");
        try {
            check(AgentRuntime.shouldRecordMethodHop(
                            "com.kalvin.kvf.modules.sys.service.UserService", "find"),
                    "hop budget resets on new request scope");
        } finally {
            AgentRuntime.releaseRequestCorrelation();
        }

        check("EXPRESSION".equals(AgentRuntime.primaryEffectKind(
                        "PROCESS", "com.ql.util.express.ExpressRunner", "execute")),
                "QLExpress execute maps to EXPRESSION effect");

        System.out.println("MethodHopBudgetAcceptanceTest: PASS");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}

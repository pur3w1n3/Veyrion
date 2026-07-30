package com.aq.jvmsentinel.analysis.entry;

/** P2-05: WebSocket / unknown protocols are UNREACHED, not fake HTTP. */
public final class NonHttpEntryProtocolAcceptanceTest {
    public static void main(String[] args) {
        var http = NonHttpEntryProtocol.classify("HTTP");
        check(http.httpProbeEligible(), "HTTP eligible");
        check("ELIGIBLE".equals(http.coverageStatus()), "HTTP ELIGIBLE");

        var ws = NonHttpEntryProtocol.classify("WebSocket");
        check(!ws.httpProbeEligible(), "WebSocket not HTTP-probe eligible");
        check("UNREACHED".equals(ws.coverageStatus()), "WebSocket UNREACHED");
        check("NON_HTTP_ADAPTER_STUB".equals(ws.reasonCode()), "WebSocket stub reason");

        var unknown = NonHttpEntryProtocol.classify("CUSTOM-RPC");
        check(!unknown.httpProbeEligible(), "unknown not eligible");
        check("UNREACHED".equals(unknown.coverageStatus()), "unknown UNREACHED");
        check("UNKNOWN_PROTOCOL".equals(unknown.reasonCode()), "unknown reason");

        var job = NonHttpEntryProtocol.classify("JOB");
        check(!job.httpProbeEligible(), "JOB not HTTP-probe eligible");
        check("NON_HTTP_ADAPTER_STUB".equals(job.reasonCode()), "JOB stub reason");
        var scheduled = NonHttpEntryProtocol.classify("SCHEDULED");
        check(!scheduled.httpProbeEligible(), "SCHEDULED not HTTP-probe eligible");

        try {
            NonHttpEntryProtocol.requireHttpOrThrow("WS");
            throw new AssertionError("WS must throw");
        } catch (IllegalArgumentException expected) {
            check("NON_HTTP_ADAPTER_STUB".equals(expected.getMessage()), "requireHttp reason");
        }

        System.out.println("NonHttpEntryProtocolAcceptanceTest: PASS");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

package com.aq.jvmsentinel.analysis.experiment;

import com.aq.jvmsentinel.AcceptanceAssertions;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/** JDBC test-connection samples must hit sandbox MySQL mock, not synthetic URL. */
public final class ProbeParameterHeuristicsJdbcAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);

        String jdbcUrl = ProbeParameterHeuristics.sampleValueFor(
                "jdbcUrl", "/common/test-connection");
        check(jdbcUrl.startsWith("jdbc:mysql://127.0.0.1:3306/"),
                "jdbcUrl sample targets loopback MySQL stub: " + jdbcUrl);
        check(!"synthetic".equals(jdbcUrl), "jdbcUrl must not be synthetic");

        String driver = ProbeParameterHeuristics.sampleValueFor(
                "driverClass", "/common/test-connection");
        check(driver.contains("mysql"), "driverClass sample is MySQL driver: " + driver);

        String user = ProbeParameterHeuristics.sampleValueFor("username", "/common/test-connection");
        String pass = ProbeParameterHeuristics.sampleValueFor("password", "/common/test-connection");
        check("veyrion".equals(user) && "veyrion".equals(pass),
                "JDBC credentials use sandbox defaults");

        String query = ProbeParameterHeuristics.buildSyntheticQuery(
                List.of("jdbcUrl", "driverClass", "username", "password"),
                "/common/test-connection");
        check(query.contains("jdbcUrl=jdbc:mysql://127.0.0.1:3306/veyrion"),
                "compiled query embeds mockable jdbcUrl: " + query);
        check(!query.contains("jdbcUrl=synthetic"),
                "compiled query must not use synthetic jdbcUrl");

        String expr = ProbeParameterHeuristics.sampleValueFor("code", "/generator/check/code");
        check("1".equals(expr), "expression heuristic unchanged");

        String uploadPath = ProbeParameterHeuristics.sampleValueFor(
                "filename", "/common/fileUpload");
        check("../veyrion-upload.bin".equals(uploadPath),
                "upload filename sample must be wire-safe traversal, got " + uploadPath);
        check(ProbeParameterHeuristics.looksUploadPath("originalfilename", "/upload"),
                "originalFilename recognized");
        String ssrfUrl = ProbeParameterHeuristics.sampleValueFor("url", "/common/fetch");
        check(ssrfUrl.startsWith("http://127.0.0.1"),
                "non-JDBC url sample must be loopback HTTP, got " + ssrfUrl);
        check(!ProbeParameterHeuristics.looksHttpUrl("jdbcUrl", "/common/test-connection"),
                "jdbcUrl must not be classified as HTTP SSRF url");

        System.out.println("ProbeParameterHeuristicsJdbcAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

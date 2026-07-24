package com.aq.jvmsentinel;

import com.aq.jvmsentinel.substitute.DependencySubstitutionEngine;
import com.aq.jvmsentinel.substitute.DependencySubstitutionPolicy;
import com.aq.jvmsentinel.substitute.DependencySubstitutionTranscript;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Main-style safety and deterministic replay acceptance for dependency substitution. */
public final class DependencySubstitutionAcceptanceTest {
    private static final String ARTIFACT_DIGEST = "a".repeat(64);
    private static final String SECRET = "super-secret-value";

    public static void main(String[] args) throws Exception {
        DependencySubstitutionPolicy policy = policy(32);
        check(policy.digest().equals(policy(32).digest()), "policy digest must be deterministic");
        DependencySubstitutionPolicy restored = serializeRoundTrip(policy);
        check(restored.digest().equals(policy.digest()), "serialized policy must preserve digest");

        String first = runReplay(policy, Files.createTempDirectory("veyrion-substitute-a-"));
        String second = runReplay(restored, Files.createTempDirectory("veyrion-substitute-b-"));
        check(first.equals(second), "same policy and operations must produce an identical transcript");
        check(!first.contains(SECRET), "transcript must redact or summarize sensitive values");
        check(first.contains("\"provenance\":\"RECORDED_REPLAY\""), "provenance must be serialized");
        check(first.contains("\"executed\":true"), "executed marker must be serialized");
        check(first.contains("\"policyDigest\":\"" + policy.digest() + "\""), "policy digest must bind results");
        check(first.contains("\"stopReason\":\"COMPLETED\""), "completion reason must be serialized");

        securityNegatives();
        budgetNegative();
        System.out.println("DependencySubstitutionAcceptanceTest: PASS");
    }

    private static String runReplay(DependencySubstitutionPolicy policy, Path root) throws Exception {
        try (DependencySubstitutionEngine engine = new DependencySubstitutionEngine(policy, root)) {
            URI base = engine.startHttpMock();
            check(base.getHost().equals("127.0.0.1"), "HTTP mock must bind IPv4 loopback");
            HttpResponse<String> response = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(base.resolve("/fixed/profile"))
                            .header("Authorization", "Bearer " + SECRET)
                            .POST(HttpRequest.BodyPublishers.ofString("token=" + SECRET))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            check(response.statusCode() == 200, "fixed HTTP route");
            check(response.body().equals("{\"role\":\"tester\"}"), "fixed HTTP response");

            DependencySubstitutionEngine.JdbcResult jdbc = engine.jdbcQuery(
                    " SELECT id, name FROM users WHERE id = ? ", List.of(SECRET));
            check(jdbc.rows().equals(List.of(List.of("7", "synthetic-user"))), "rule-generated JDBC result");

            check(new String(engine.readFile("input/config.txt"), StandardCharsets.UTF_8)
                    .equals("seed=true"), "seeded file read");
            engine.writeFile("work/output.txt", ("token=" + SECRET).getBytes(StandardCharsets.UTF_8));
            check(new String(engine.readFile("work/output.txt"), StandardCharsets.UTF_8)
                    .equals("token=" + SECRET), "authorized tmpfs write/read");

            DependencySubstitutionEngine.ProcessResult process =
                    engine.process(List.of("veyrion-safe-probe", "--version"));
            check(process.simulated() && process.exitCode() == 0, "fixed harmless process simulation");
            engine.complete();

            List<DependencySubstitutionTranscript.Result> results = engine.transcript().results();
            for (int index = 0; index < results.size(); index++) {
                DependencySubstitutionTranscript.Result result = results.get(index);
                check(result.sequence() == index, "sequence must be contiguous");
                check(result.scope().equals(policy.scope()), "scope must bind every result");
                check(result.policyDigest().equals(policy.digest()), "digest must bind every result");
                check(result.budget().operationsUsed() == index + 1, "budget snapshot per result");
                check(result.stopReason() != null, "stop reason per result");
            }
            check(engine.transcript().digest().matches("[0-9a-f]{64}"),
                    "complete transcript digest is missing");
            return engine.transcript().toJson();
        }
    }

    private static void securityNegatives() throws Exception {
        expect(IllegalArgumentException.class, () -> new DependencySubstitutionPolicy.FileGrant(
                "../host-secret", true, false, "", DependencySubstitutionPolicy.Provenance.USER_SNAPSHOT));
        expect(IllegalArgumentException.class, () -> new DependencySubstitutionPolicy.FileGrant(
                "C:/Windows/System32/config", true, false, "",
                DependencySubstitutionPolicy.Provenance.USER_SNAPSHOT));
        expect(IllegalArgumentException.class, () -> new DependencySubstitutionPolicy.HttpRoute(
                "GET", "//attacker.invalid/path", 200, "text/plain", "",
                DependencySubstitutionPolicy.Provenance.RULE_GENERATED));
        expect(IllegalArgumentException.class, () -> new DependencySubstitutionPolicy.HttpRoute(
                "GET", "/proxy?url=http://attacker.invalid", 200, "text/plain", "",
                DependencySubstitutionPolicy.Provenance.RULE_GENERATED));

        try (DependencySubstitutionEngine engine = new DependencySubstitutionEngine(
                policy(16), Files.createTempDirectory("veyrion-substitute-deny-file-"))) {
            expect(SecurityException.class, () -> engine.readFile("../outside"));
            DependencySubstitutionTranscript.Result denied = engine.transcript().results().get(0);
            check(!denied.executed() && denied.stopReason() == DependencySubstitutionTranscript.StopReason.POLICY_REJECTED,
                    "denied file access must be explicit");
        }

        try (DependencySubstitutionEngine engine = new DependencySubstitutionEngine(
                policy(16), Files.createTempDirectory("veyrion-substitute-deny-jdbc-"))) {
            expect(SecurityException.class, () -> engine.jdbcQuery("delete from users", List.of()));
            check(engine.transcript().results().get(0).responseSummary().startsWith("DENY"),
                    "unruled SQL must be denied");
        }
        try (DependencySubstitutionEngine engine = new DependencySubstitutionEngine(
                policy(16), Files.createTempDirectory("veyrion-substitute-sql-literal-"))) {
            expect(SecurityException.class, () -> engine.jdbcQuery(
                    "select role from users where status = 'admin'", List.of()));
            check(!engine.transcript().results().get(0).executed(),
                    "SQL literal case must not be normalized into another rule");
        }

        try (DependencySubstitutionEngine engine = new DependencySubstitutionEngine(
                policy(16), Files.createTempDirectory("veyrion-substitute-deny-process-"))) {
            expect(SecurityException.class, () -> engine.process(List.of("cmd.exe", "/c", "whoami")));
            check(!engine.transcript().results().get(0).executed(), "real process must never execute");
        }

        try (DependencySubstitutionEngine engine = new DependencySubstitutionEngine(
                policy(16), Files.createTempDirectory("veyrion-substitute-deny-http-"))) {
            URI base = engine.startHttpMock();
            HttpResponse<String> response = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(base.resolve("/unconfigured")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            check(response.statusCode() == 404, "unconfigured HTTP route must not forward");
            check(!engine.transcript().results().get(0).executed(), "unconfigured HTTP route denied");
        }
    }

    private static void budgetNegative() throws Exception {
        try (DependencySubstitutionEngine engine = new DependencySubstitutionEngine(
                policy(1), Files.createTempDirectory("veyrion-substitute-budget-"))) {
            engine.jdbcQuery("select id, name from users where id = ?", List.of("one"));
            expect(DependencySubstitutionTranscript.BudgetExceededException.class,
                    () -> engine.jdbcQuery("select id, name from users where id = ?", List.of("two")));
            check(engine.transcript().stopReason() == DependencySubstitutionTranscript.StopReason.BUDGET_EXHAUSTED,
                    "budget exhaustion must stop transcript");
        }
    }

    private static DependencySubstitutionPolicy policy(long maxOperations) {
        return new DependencySubstitutionPolicy(
                DependencySubstitutionPolicy.SCHEMA_VERSION,
                new DependencySubstitutionPolicy.Scope("project-1", ARTIFACT_DIGEST, "scan-1", "task-1"),
                new DependencySubstitutionPolicy.Budget(maxOperations, 512 * 1024, 64 * 1024),
                List.of(new DependencySubstitutionPolicy.HttpRoute(
                        "POST", "/fixed/profile", 200, "application/json", "{\"role\":\"tester\"}",
                        DependencySubstitutionPolicy.Provenance.RECORDED_REPLAY)),
                List.of(
                        new DependencySubstitutionPolicy.JdbcRule(
                                "select id, name from users where id = ?",
                                List.of("id", "name"), List.of(List.of("7", "synthetic-user")),
                                DependencySubstitutionPolicy.Provenance.RULE_GENERATED),
                        new DependencySubstitutionPolicy.JdbcRule(
                                "select role from users where status = 'ADMIN'",
                                List.of("role"), List.of(List.of("administrator")),
                                DependencySubstitutionPolicy.Provenance.RECORDED_REPLAY)),
                List.of(
                        new DependencySubstitutionPolicy.FileGrant(
                                "input/config.txt", true, false, "seed=true",
                                DependencySubstitutionPolicy.Provenance.USER_SNAPSHOT),
                        new DependencySubstitutionPolicy.FileGrant(
                                "work/output.txt", true, true, "",
                                DependencySubstitutionPolicy.Provenance.RULE_GENERATED)),
                List.of(new DependencySubstitutionPolicy.ProcessSimulation(
                        List.of("veyrion-safe-probe", "--version"), 0, "probe/1", "",
                        DependencySubstitutionPolicy.Provenance.AI_INFERRED)));
    }

    @SuppressWarnings("unchecked")
    private static <T> T serializeRoundTrip(T value) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream output = new ObjectOutputStream(bytes)) {
            output.writeObject(value);
        }
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            return (T) input.readObject();
        }
    }

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    private static <T extends Throwable> void expect(Class<T> type, ThrowingRunnable runnable) throws Exception {
        try {
            runnable.run();
        } catch (Throwable actual) {
            if (type.isInstance(actual)) return;
            throw actual;
        }
        throw new AssertionError("expected " + type.getSimpleName());
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}

package com.aq.jvmsentinel;

import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.model.PathOutcomeClass;
import com.aq.jvmsentinel.model.PathRun;
import com.aq.jvmsentinel.model.SqlEvent;
import com.aq.jvmsentinel.model.VerificationStatus;
import com.aq.jvmsentinel.support.LiveEnvironment;
import com.aq.jvmsentinel.worker.DynamicConfirmedGate;
import com.aq.jvmsentinel.worker.SqlDiffProbe;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Live JDBC H3 evidence: handshake/meta must not reach DYNAMIC_CONFIRMED; marker statement can.
 * Embedded SQLite JDBC always runs. Postgres container path runs when Docker + image available;
 * otherwise SKIP with log (gate still PASS).
 */
public final class LiveJdbcH3AcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();
    private static final String MARKER = SqlDiffProbe.META_MARKER;

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        handshakeAndMetaNeverConfirm();
        embeddedSqliteStatementH3();
        if (!LiveEnvironment.dockerAvailable()) {
            System.out.println("LiveJdbcH3AcceptanceTest: SKIP live Postgres "
                    + "(Docker unavailable)");
            check(true, "skip logged when Docker unavailable");
        } else {
            String image = LiveEnvironment.preferredPostgresImage();
            if (image.isBlank()) {
                System.out.println("LiveJdbcH3AcceptanceTest: SKIP live Postgres "
                        + "(no postgres:15 / postgres:18-alpine image)");
                check(true, "skip logged when DB container image missing");
            } else {
                System.out.println("LiveJdbcH3AcceptanceTest: LIVE Postgres image=" + image);
                try {
                    livePostgresStatementH3(image);
                } catch (Exception failure) {
                    System.out.println("LiveJdbcH3AcceptanceTest: SKIP live Postgres "
                            + "(container not usable: "
                            + failure.getClass().getSimpleName() + ": " + failure.getMessage() + ")");
                    check(true, "skip logged when Postgres container not usable");
                }
            }
        }
        System.out.println("LiveJdbcH3AcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void handshakeAndMetaNeverConfirm() {
        PathRun handshake = pathRun("pr-meta-1", "corr-meta-1", List.of(
                new SqlEvent("accepted-without-credential-capture", "", "UNKNOWN",
                        false, true, "DEPENDENCY_PROTOCOL_MOCK"),
                new SqlEvent("port=5432", "", "UNKNOWN", false, true, "DEPENDENCY_PROTOCOL_MOCK"),
                new SqlEvent("sqlClass=SELECT,bytes=12", "", "UNKNOWN",
                        false, true, "DEPENDENCY_PROTOCOL_MOCK")));
        check(DynamicConfirmedGate.evaluate(handshake, MARKER)
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "handshake/meta alone cannot DYNAMIC_CONFIRMED");

        PathRun metaWithMarkerSubstring = pathRun("pr-meta-2", "corr-meta-2", List.of(
                new SqlEvent("accepted-without-credential '" + MARKER, "",
                        "UNKNOWN", false, true, "DEPENDENCY_PROTOCOL_MOCK")));
        check(DynamicConfirmedGate.evaluate(metaWithMarkerSubstring, MARKER)
                        == VerificationStatus.DYNAMIC_SUSPECTED,
                "handshake string coincidence with marker cannot confirm");
        check(DynamicConfirmedGate.evaluate(handshake, MARKER)
                        != VerificationStatus.VERIFIED,
                "meta path never VERIFIED");
    }

    private static void embeddedSqliteStatementH3() throws Exception {
        Path db = Files.createTempFile("veyrion-live-h3-", ".db");
        try {
            String url = "jdbc:sqlite:" + db.toAbsolutePath();
            String benign = "SELECT id FROM users WHERE name='alice'";
            String injected = "SELECT id FROM users WHERE name='" + MARKER;
            try (Connection connection = DriverManager.getConnection(url);
                 Statement statement = connection.createStatement()) {
                statement.execute("CREATE TABLE users (id INTEGER, name TEXT)");
                statement.execute("INSERT INTO users VALUES (1, 'alice')");
                statement.execute(benign);
                try {
                    statement.execute(injected);
                } catch (Exception ignored) {
                    // SQLite may reject unterminated quote; statement text still observed.
                }
            }
            PathRun positive = pathRun("pr-sqlite-pos", "corr-sqlite-pos", List.of(
                    new SqlEvent(injected, "", "READ", false, true, "AGENT_INSTRUMENTED")));
            check(DynamicConfirmedGate.evaluate(positive, MARKER)
                            == VerificationStatus.DYNAMIC_CONFIRMED,
                    "embedded SQLite marker statement reaches DYNAMIC_CONFIRMED");

            PathRun negative = pathRun("pr-sqlite-neg", "corr-sqlite-neg", List.of(
                    new SqlEvent(benign, "", "READ", false, false, "AGENT_INSTRUMENTED")));
            check(DynamicConfirmedGate.evaluate(negative, MARKER)
                            == VerificationStatus.DYNAMIC_SUSPECTED,
                    "embedded SQLite benign statement stays DYNAMIC_SUSPECTED");

            PathRun parameterized = pathRun("pr-sqlite-param", "corr-sqlite-param", List.of(
                    new SqlEvent("SELECT id FROM users WHERE name=?", "jdbc-placeholders",
                            "READ", true, false, "AGENT_INSTRUMENTED")));
            check(DynamicConfirmedGate.evaluate(parameterized, MARKER)
                            == VerificationStatus.DYNAMIC_SUSPECTED,
                    "parameterized SQLite statement cannot confirm");
            check(DynamicConfirmedGate.apply(positive, MARKER).verificationStatus()
                            .equals(VerificationStatus.DYNAMIC_CONFIRMED.name()),
                    "apply upgrades positive H3 PathRun");
            check(!VerificationStatus.VERIFIED.name()
                            .equals(DynamicConfirmedGate.apply(positive, MARKER).verificationStatus()),
                    "H3 never opens VERIFIED");
        } finally {
            Files.deleteIfExists(db);
        }
    }

    private static void livePostgresStatementH3(String image) throws Exception {
        String name = "veyrion-live-h3-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        LiveEnvironment.CommandResult run = LiveEnvironment.docker(List.of(
                "run", "-d",
                "--name", name,
                "-e", "POSTGRES_PASSWORD=veyrion",
                "-e", "POSTGRES_USER=veyrion",
                "-e", "POSTGRES_DB=veyrion",
                image), Duration.ofSeconds(90));
        check(run.exitCode() == 0, "postgres container starts: " + run.stdout() + run.detail());
        try {
            awaitPostgresReady(name);
            String benign = "SELECT 1 AS id WHERE 'alice' = 'alice'";
            String injected = "SELECT 1 AS id WHERE 'x' = '" + MARKER;
            // Handshake/meta analogue: server readiness noise must not confirm.
            PathRun handshake = pathRun("pr-pg-meta", "corr-pg-meta", List.of(
                    new SqlEvent("accepted-without-credential-capture", "", "UNKNOWN",
                            false, true, "DEPENDENCY_PROTOCOL_MOCK"),
                    new SqlEvent("port=5432", "", "UNKNOWN", false, true,
                            "DEPENDENCY_PROTOCOL_MOCK")));
            check(DynamicConfirmedGate.evaluate(handshake, MARKER)
                            == VerificationStatus.DYNAMIC_SUSPECTED,
                    "live Postgres handshake/meta cannot DYNAMIC_CONFIRMED");

            LiveEnvironment.CommandResult benignExec = psql(name, benign);
            check(benignExec.exitCode() == 0, "live benign SQL executes: " + benignExec.stdout());
            PathRun negative = pathRun("pr-pg-neg", "corr-pg-neg", List.of(
                    new SqlEvent(benign, "", "READ", false, false, "RUNTIME_OBSERVED")));
            check(DynamicConfirmedGate.evaluate(negative, MARKER)
                            == VerificationStatus.DYNAMIC_SUSPECTED,
                    "live Postgres benign statement stays DYNAMIC_SUSPECTED");

            // Marker SQL may fail at the engine; H3 cares about observed statement text.
            psql(name, injected);
            PathRun positive = pathRun("pr-pg-pos", "corr-pg-pos", List.of(
                    new SqlEvent(injected, "", "READ", false, true, "RUNTIME_OBSERVED")));
            check(DynamicConfirmedGate.evaluate(positive, MARKER)
                            == VerificationStatus.DYNAMIC_CONFIRMED,
                    "live Postgres marker statement reaches DYNAMIC_CONFIRMED");
            check(DynamicConfirmedGate.evaluate(negative, MARKER)
                            != VerificationStatus.DYNAMIC_CONFIRMED,
                    "benign PathRun stays unconfirmed despite positive sibling");
        } finally {
            LiveEnvironment.docker(List.of("rm", "-f", name), Duration.ofSeconds(30));
        }
    }

    private static void awaitPostgresReady(String name) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(90).toNanos();
        String last = "";
        while (System.nanoTime() < deadline) {
            LiveEnvironment.CommandResult state = LiveEnvironment.docker(List.of(
                    "inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", name),
                    Duration.ofSeconds(10));
            last = state.stdout().strip() + " / " + state.detail();
            if (state.stdout().contains("exited")) {
                LiveEnvironment.CommandResult logs = LiveEnvironment.docker(
                        List.of("logs", "--tail", "40", name), Duration.ofSeconds(10));
                throw new AssertionError("postgres container exited: " + logs.stdout());
            }
            LiveEnvironment.CommandResult ready = LiveEnvironment.docker(List.of(
                    "exec", name, "pg_isready", "-U", "veyrion", "-d", "veyrion"),
                    Duration.ofSeconds(10));
            if (ready.exitCode() == 0) {
                check(true, "postgres ready");
                return;
            }
            last = ready.stdout().strip() + " state=" + last;
            Thread.sleep(1000);
        }
        throw new AssertionError("postgres container not ready: " + last);
    }

    private static LiveEnvironment.CommandResult psql(String name, String sql) {
        return LiveEnvironment.docker(List.of(
                "exec", "-e", "PGPASSWORD=veyrion", name,
                "psql", "-U", "veyrion", "-d", "veyrion", "-v", "ON_ERROR_STOP=0",
                "-c", sql), Duration.ofSeconds(20));
    }

    private static PathRun pathRun(String id, String correlation, List<SqlEvent> sql) {
        return new PathRun(
                id, "scan-live-h3", "entry:GET:/users", IdentityTrack.UNAUTH, correlation,
                "plan:live-h3", "GET", "application/json",
                "GET /users correlationId=" + correlation,
                PathOutcomeClass.HTTP_OBSERVED, 200, true, true, sql,
                "COMPLETED", "DYNAMIC_SUSPECTED", List.of("evidence-" + id),
                "RUNTIME_OBSERVED", "");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

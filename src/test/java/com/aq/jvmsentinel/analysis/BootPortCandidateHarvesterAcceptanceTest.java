package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.AcceptanceAssertions;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/** P0-17: Boot config port harvest rejects dependency listeners. */
public final class BootPortCandidateHarvesterAcceptanceTest {
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    public static void main(String[] args) {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        propertiesPort();
        yamlServerBlock();
        dependencyPortsRejected();
        System.out.println("BootPortCandidateHarvesterAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    private static void propertiesPort() {
        BootPortCandidateHarvester.Harvest harvest = BootPortCandidateHarvester.harvest(
                List.of("server.port=9090", "spring.datasource.url=jdbc:mysql://127.0.0.1:3306/x"),
                List.of("Start-Class: com.example.DemoApplication"));
        check(harvest.candidateHttpPorts().contains(9090), "properties server.port harvested");
        check("com.example.DemoApplication".equals(harvest.startClass()), "Start-Class harvested");
        check(!harvest.candidateHttpPorts().contains(3306), "jdbc port not an HTTP candidate");
    }

    private static void yamlServerBlock() {
        BootPortCandidateHarvester.Harvest harvest = BootPortCandidateHarvester.harvest(List.of(
                "server:",
                "  port: 8088",
                "spring:",
                "  redis:",
                "    port: 6379"));
        check(harvest.candidateHttpPorts().contains(8088), "yaml server.port harvested");
        check(harvest.rejectedDependencyPorts().contains(6379)
                        || !harvest.candidateHttpPorts().contains(6379),
                "redis port not treated as app HTTP port");
    }

    private static void dependencyPortsRejected() {
        BootPortCandidateHarvester.Harvest harvest = BootPortCandidateHarvester.harvest(
                List.of("server.port=5432", "server.port=8080"));
        check(harvest.rejectedDependencyPorts().contains(5432), "5432 rejected as dependency");
        check(harvest.candidateHttpPorts().contains(8080), "8080 kept");
        check(BootPortCandidateHarvester.isDependencyPort(3306), "3306 dependency");
        check(!BootPortCandidateHarvester.isDependencyPort(8443), "8443 not dependency");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}

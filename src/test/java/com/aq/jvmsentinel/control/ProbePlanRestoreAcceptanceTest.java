package com.aq.jvmsentinel.control;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.control.service.ProbePlanService;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.aq.jvmsentinel.worker.NetworkPolicy;
import com.aq.jvmsentinel.worker.ResourceBudget;
import com.aq.jvmsentinel.worker.TaskLifecycle;
import com.aq.jvmsentinel.worker.TaskSnapshot;
import com.aq.jvmsentinel.worker.WorkerCapability;
import com.aq.jvmsentinel.worker.WorkerTaskSpec;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * 启动 restore 从 durable V026 payload 水合 probe plan，无需 identity harvest。
 */
public final class ProbePlanRestoreAcceptanceTest {
    private ProbePlanRestoreAcceptanceTest() { }

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        hydrateRoundTripPreservesStoredAuthMarker();
        missingPayloadFailsClosedWithoutInventing();
        controlPlaneStartupRestoresFromPayloadWithoutHarvest();
        System.out.println("ProbePlanRestoreAcceptanceTest: PASS ("
                + AcceptanceAssertions.get() + " assertions)");
    }

    private static void hydrateRoundTripPreservesStoredAuthMarker() {
        String marker = "Bearer STORED-RESTORE-MARKER";
        ApiDtos.EntryDto primary = entry("project-restore", "a".repeat(64), "scan-restore", "entry-1");
        ProbePlanService.ProbePlan plan = new ProbePlanService.ProbePlan(
                primary,
                List.of(new ExternalArtifactTaskExecutor.ProbeTarget(
                        "GET", "/api/admin", "", "ADMIN", marker, "", "plan:restore-1", "")),
                List.of());
        String payload = ProbePlanService.serializePlanPayload(plan);
        check(payload != null && payload.contains("STORED-RESTORE-MARKER"),
                "serialized payload retains marker");
        ProbePlanService.ProbePlan hydrated = ProbePlanService.hydrateFromStoredPayload(payload);
        check(hydrated != null && hydrated.primary() != null
                        && "entry-1".equals(hydrated.primary().id()),
                "hydrate restores primary");
        check(hydrated.probes().size() == 1
                        && marker.equals(hydrated.probes().get(0).authHeader()),
                "hydrate restores stored auth header without harvest");
    }

    private static void missingPayloadFailsClosedWithoutInventing() {
        check(ProbePlanService.hydrateFromStoredPayload(null) == null,
                "null payload returns null (legacy row)");
        check(ProbePlanService.hydrateFromStoredPayload("   ") == null,
                "blank payload returns null");
        boolean threw = false;
        try {
            ProbePlanService.hydrateFromStoredPayload("{\"schemaVersion\":1}");
        } catch (IllegalArgumentException expected) {
            threw = true;
        }
        check(threw, "corrupt payload fails closed");
    }

    private static void controlPlaneStartupRestoresFromPayloadWithoutHarvest() throws Exception {
        Path root = Files.createTempDirectory("veyrion-probe-restore");
        Path database = root.resolve("state").resolve("control-plane.db");
        Files.createDirectories(database.getParent());
        String now = Instant.now().toString();
        String digest = "c".repeat(64);
        String scanId = "scan-restore-startup";
        String taskId = "task-dynamic-restore01";
        String entryId = "entry-restore-1";
        String marker = "Bearer STORED-RESTORE-MARKER";

        ControlPlaneStore store = ControlPlaneStore.sqlite(database, root);
        store.bootstrapOperator("restore-token", now);
        var project = store.createProject("project-restore-startup", "Restore startup", now, "local-admin");
        Path artifact = root.resolve("fixture.jar");
        Files.writeString(artifact, "not-a-real-jar-bytes");
        store.registerArtifact(project, new ArtifactDescriptor(
                "artifact-restore", ArtifactType.JAR, artifact, Files.size(artifact), digest,
                true, Instant.parse(now), "fixture.jar"), "local-admin");

        ApiDtos.EntryDto entry = entry(project.projectId(), digest, scanId, entryId);
        ApiDtos.ScanDto scan = new ApiDtos.ScanDto(ApiDtos.SCHEMA_VERSION, project.projectId(), digest, scanId,
                "COMPLETED", ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, now, now,
                List.of(), List.of(entry), List.of(), List.of(), List.of(), List.of());
        store.saveScan(new ControlPlaneStore.ScanRecord(scan, Map.of(), List.of(), List.of()), "local-admin");

        ResourceBudget budget = new ResourceBudget(60, 60_000, 256L * 1024 * 1024,
                256L * 1024 * 1024, 8L * 1024 * 1024);
        WorkerTaskSpec spec = new WorkerTaskSpec(
                WorkerControlPlaneApi.CONTRACT_VERSION,
                project.projectId(), digest, scanId, taskId, entryId, true,
                budget, NetworkPolicy.denyAll(), WorkerCapability.TRUSTED_DOCKER);
        store.persistWorkerTask(new TaskSnapshot(
                WorkerControlPlaneApi.CONTRACT_VERSION, spec, TaskLifecycle.QUEUED,
                null, null, null, null, Instant.parse(now)));

        ProbePlanService.ProbePlan storedPlan = new ProbePlanService.ProbePlan(
                entry,
                List.of(new ExternalArtifactTaskExecutor.ProbeTarget(
                        "GET", "/api/admin", "", "ADMIN", marker, "", "", "")),
                List.of());
        String inputsJson = "[]";
        int maxRequests = 1;
        String planHash = sha256(scanId + "\n" + entryId + "\n" + inputsJson + "\n" + maxRequests);
        store.persistProbePlan(new SQLiteControlPlanePersistence.ProbePlanData(
                taskId, project.projectId(), digest, scanId, entryId, inputsJson, maxRequests,
                planHash, now, ProbePlanService.serializePlanPayload(storedPlan)));

        // 无 payload 的遗留行须跳过，不得经 harvest 重建。
        store.persistProbePlan(new SQLiteControlPlanePersistence.ProbePlanData(
                "task-dynamic-legacy02", project.projectId(), digest, scanId, entryId, inputsJson,
                maxRequests, planHash, now, null));
        WorkerTaskSpec legacySpec = new WorkerTaskSpec(
                WorkerControlPlaneApi.CONTRACT_VERSION,
                project.projectId(), digest, scanId, "task-dynamic-legacy02", entryId, true,
                budget, NetworkPolicy.denyAll(), WorkerCapability.TRUSTED_DOCKER);
        store.persistWorkerTask(new TaskSnapshot(
                WorkerControlPlaneApi.CONTRACT_VERSION, legacySpec, TaskLifecycle.QUEUED,
                null, null, null, null, Instant.parse(now)));

        long started = System.nanoTime();
        try (ControlPlaneServer server = new ControlPlaneServer(root, 0, "restore-token", database).start()) {
            double seconds = (System.nanoTime() - started) / 1_000_000_000.0;
            ProbePlanService.ProbePlan restored = server.restoredDynamicProbePlan(taskId);
            check(restored != null, "payload-backed plan restored into memory");
            check(restored.probes().size() == 1
                            && marker.equals(restored.probes().get(0).authHeader()),
                    "restored plan keeps stored auth marker (proves no rebuild/harvest)");
            check(server.restoredDynamicProbePlan("task-dynamic-legacy02") == null,
                    "legacy row without payload is skipped (fail closed, no invent/harvest)");
            check(seconds < 15.0, "startup restore completes quickly without JAR harvest");
        }
    }

    private static ApiDtos.EntryDto entry(String projectId, String digest, String scanId, String id) {
        return new ApiDtos.EntryDto(ApiDtos.SCHEMA_VERSION, projectId, digest, scanId,
                id, "HTTP", "GET", "/api/admin", "com.example.AdminController", "example",
                List.of(), List.of(), ApiDtos.STATIC_INFERRED, 0.9, 0, List.of());
    }

    private static String sha256(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        AcceptanceAssertions.record();
    }
}

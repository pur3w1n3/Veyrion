package com.aq.jvmsentinel.control.service.probe;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.service.ProbePlanService;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** 探针计划 durable JSON 序列化与反序列化。 */
public final class ProbePlanPayloadCodec {
    private static final int STORED_PROBE_PLAN_SCHEMA = 1;
    private static final ObjectMapper PAYLOAD_JSON = new ObjectMapper();

    private ProbePlanPayloadCodec() {
    }

    /**
     * 将已编译探针计划序列化为可持久化 payload；不做 harvest 或重建。
     */
    public static String serializePlanPayload(ProbePlanService.ProbePlan plan) {
        Objects.requireNonNull(plan, "plan");
        if (plan.primary() == null) {
            throw new IllegalArgumentException("probe plan primary entry is required");
        }
        List<ExternalArtifactTaskExecutor.ProbeTarget> probes =
                plan.probes() == null ? List.of() : plan.probes();
        if (probes.isEmpty() || probes.size() > ProbePlanService.MAX_DYNAMIC_PROBES) {
            throw new IllegalArgumentException("probe plan probe count is out of bounds");
        }
        try {
            String json = PAYLOAD_JSON.writeValueAsString(new ProbePlanService.StoredProbePlanPayload(
                    STORED_PROBE_PLAN_SCHEMA, plan.primary(), probes,
                    plan.unreachedPaths() == null ? List.of() : plan.unreachedPaths()));
            if (json.length() > ProbePlanService.MAX_PROBE_PLAN_PAYLOAD_BYTES) {
                throw new IllegalArgumentException("probe plan payload exceeds durable size budget");
            }
            return json;
        } catch (IllegalArgumentException invalid) {
            throw invalid;
        } catch (Exception failure) {
            throw new IllegalArgumentException("probe plan payload could not be serialized", failure);
        }
    }

    /**
     * 从已存储 payload 水合内存探针计划，不做 identity harvest。
     * payload 缺失时返回 {@code null}（遗留行）；损坏时抛异常。
     */
    public static ProbePlanService.ProbePlan hydrateFromStoredPayload(String payloadJson) {
        if (payloadJson == null || payloadJson.isBlank()) {
            return null;
        }
        if (payloadJson.length() > ProbePlanService.MAX_PROBE_PLAN_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("probe plan payload exceeds durable size budget");
        }
        try {
            ProbePlanService.StoredProbePlanPayload stored = PAYLOAD_JSON.readValue(
                    payloadJson, ProbePlanService.StoredProbePlanPayload.class);
            if (stored == null || stored.schemaVersion() != STORED_PROBE_PLAN_SCHEMA) {
                throw new IllegalArgumentException("unsupported probe plan payload schema");
            }
            if (stored.primary() == null) {
                throw new IllegalArgumentException("probe plan payload missing primary entry");
            }
            List<ExternalArtifactTaskExecutor.ProbeTarget> probes =
                    stored.probes() == null ? List.of() : List.copyOf(stored.probes());
            if (probes.isEmpty() || probes.size() > ProbePlanService.MAX_DYNAMIC_PROBES) {
                throw new IllegalArgumentException("probe plan payload probe count is out of bounds");
            }
            // 经校验构造函数重建 ProbeTarget（fail closed）。
            List<ExternalArtifactTaskExecutor.ProbeTarget> validated = new ArrayList<>(probes.size());
            for (ExternalArtifactTaskExecutor.ProbeTarget probe : probes) {
                if (probe == null) {
                    throw new IllegalArgumentException("probe plan payload contains a null probe");
                }
                validated.add(new ExternalArtifactTaskExecutor.ProbeTarget(
                        probe.method(), probe.route(), probe.query(), probe.track(),
                        probe.authHeader(), probe.bladeAuthHeader(), probe.experimentPlanId(),
                        probe.cookieHeader(), probe.listenPort()));
            }
            List<ApiDtos.PathDto> unreached = stored.unreachedPaths() == null
                    ? List.of() : List.copyOf(stored.unreachedPaths());
            return new ProbePlanService.ProbePlan(stored.primary(), List.copyOf(validated), unreached);
        } catch (IllegalArgumentException invalid) {
            throw invalid;
        } catch (Exception failure) {
            throw new IllegalArgumentException("probe plan payload is corrupt or incomplete", failure);
        }
    }

}

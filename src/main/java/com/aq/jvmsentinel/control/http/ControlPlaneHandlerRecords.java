package com.aq.jvmsentinel.control.http;

import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.worker.TaskSnapshot;

import java.util.List;
import java.util.Map;

/** 处理器间共享的私有记录类型。 */
public final class ControlPlaneHandlerRecords {
    private ControlPlaneHandlerRecords() {}

    public record ScanBuild(ApiDtos.ScanDto scan, Map<String, ApiDtos.EvidenceDto> evidence,
                            List<ApiDtos.FindingDto> findings, List<ApiDtos.AttackChainDto> chains,
                            StaticFactSnapshot staticFacts, List<SecurityHypothesis> hypotheses) {
        public ScanBuild {
            hypotheses = List.copyOf(hypotheses == null ? List.of() : hypotheses);
        }
    }

    public record ScanStart(ControlPlaneStore.ScanRecord scan, boolean replayed) { }

    public record AuditRunReplay(String payload, String scanId, String preAnalysisJobId) { }

    public record DynamicTaskPayload(String scanId, String artifactDigest, String targetEntryId) { }

    public record DynamicTaskReplay(DynamicTaskPayload payload, TaskSnapshot snapshot) { }

    public record FindingReplay(String scanId, TaskSnapshot snapshot) { }

    public record EntryFocusProbe(String scanId, String entryId, TaskSnapshot snapshot) { }
}

package com.aq.jvmsentinel.control.store;

import com.aq.jvmsentinel.analysis.experiment.PostureExperimentCompiler;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.StaticFactSnapshot;
import com.aq.jvmsentinel.domain.experiment.HypothesisExperimentPlan;
import com.aq.jvmsentinel.domain.hypothesis.SecurityHypothesis;
import com.aq.jvmsentinel.domain.ir.ProgramNode;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.model.ArtifactDescriptor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Store 辅助类。 */
public final class ControlPlaneMemoryState {
    public final Map<String, ControlPlaneStore.ProjectRecord> projects = new ConcurrentHashMap<>();
    public final Map<String, ControlPlaneStore.ScanRecord> scans = new ConcurrentHashMap<>();
    public final Map<String, ApiDtos.FindingDto> findings = new ConcurrentHashMap<>();
    public final Map<String, ApiDtos.EvidenceDto> evidence = new ConcurrentHashMap<>();
    public final Map<String, ApiDtos.AttackChainDto> chains = new ConcurrentHashMap<>();
    public final Map<String, StaticFactSnapshot> staticFacts = new ConcurrentHashMap<>();
    public final Map<String, List<SecurityHypothesis>> hypothesesByScan = new ConcurrentHashMap<>();
    public final Map<String, SecurityHypothesis> hypothesesById = new ConcurrentHashMap<>();
    /** 作用域索引：允许不同 scan 使用相同 hypothesisId 而不交叉关联。 */
    public final Map<String, SecurityHypothesis> hypothesesByScopedId = new ConcurrentHashMap<>();
    /** P1-08：LanguageAnalyzer / Test Analyzer ProgramNode 叠加层（进程内）。 */
    public final Map<String, List<ProgramNode>> analyzerProgramNodesByScan = new ConcurrentHashMap<>();
    /** P1-06：假设绑定的实验计划（进程内；保持 experimentPlanId 身份）。 */
    public final Map<String, List<HypothesisExperimentPlan>> hypothesisPlansByScan = new ConcurrentHashMap<>();
    public final Map<String, HypothesisExperimentPlan> hypothesisPlansById = new ConcurrentHashMap<>();
    /** experimentPlanId / pathRunId 到 hypothesisId+planKind 的 probe 绑定。 */
    public final Map<String, ControlPlaneStore.ProbeHypothesisBinding> probeHypothesisBindings =
            new ConcurrentHashMap<>();
    /** P0-21：服务端编译的姿态实验计划，按 experimentPlanId 索引。 */
    public final Map<String, PostureExperimentCompiler.CompiledPostureExperiment> postureExperimentsById =
            new ConcurrentHashMap<>();
    /** pathRunId 到最新 PathTrace，供 API 富化查询。 */
    public final Map<String, PathTrace> pathTracesByPathRunId = new ConcurrentHashMap<>();
    /** 最新 PathTrace 的 Evidence Graph delta 线格式映射，按 pathTraceId 索引。 */
    public final Map<String, Map<String, Object>> pathTraceEvidenceDeltas = new ConcurrentHashMap<>();
    public final List<ControlPlaneStore.ObservationKindRef> pendingIncrementalSubjects = new ArrayList<>();
}

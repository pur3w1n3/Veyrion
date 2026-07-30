package com.aq.jvmsentinel.analysis.executor;

import com.aq.jvmsentinel.analysis.ClassMetadata;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * ElasticJob / 类 Quartz HTTP 触发的轻量启发式（第三适配器骨架）。
 *
 * <p>默认产出可观测 {@code JOB} protocol（非 HTTP 探针目标），避免把
 * {@code @Scheduled}/纯 ZK 调度硬造成 MVC 入口。仅当配置出现明确 HTTP 触发
 * 前缀时，额外产出 HTTP 回调候选。
 */
public final class ElasticJobHttpEntryAdapter implements ExecutorEntryAdapter {
    public static final String ID = "elastic-job-http";
    public static final String FRAMEWORK = "elastic-job";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String frameworkId() {
        return FRAMEWORK;
    }

    @Override
    public boolean matches(ExecutorEntryContext context) {
        if (context == null) {
            return false;
        }
        return context.classNameContains("org.apache.shardingsphere.elasticjob")
                || context.classNameContains("com.dangdang.ddframe.job")
                || context.classNameContains("ElasticJob")
                || context.archiveEntryContains("elastic-job")
                || context.archiveEntryContains("elasticjob")
                || context.configContains("elasticjob")
                || context.configContains("elastic-job")
                || hasJobAnnotation(context);
    }

    @Override
    public List<RuntimeCallbackEntry> discover(ExecutorEntryContext context) {
        if (!matches(context)) {
            return List.of();
        }
        List<RuntimeCallbackEntry> out = new ArrayList<>();
        String signal = hasJobAnnotation(context) ? "annotation:ElasticJobConfiguration"
                : context.archiveEntryContains("elastic-job") || context.archiveEntryContains("elasticjob")
                ? "archive:elastic-job"
                : "class/config:elastic-job";

        // 可观测 JOB 面：不进入 HTTP 探针（NonHttpEntryProtocol → UNREACHED）。
        out.add(new RuntimeCallbackEntry(
                ID,
                FRAMEWORK,
                "JOB",
                "HANDLE",
                "job:elastic-job",
                "org.apache.shardingsphere.elasticjob",
                List.of("schedule:elastic-job"),
                List.of("framework:" + FRAMEWORK, "callbackKind:scheduled-job"),
                "executor-adapter:" + ID + ":job-surface",
                "ElasticJob / similar scheduler presence=" + signal
                        + "; no fabricated MVC route; JOB protocol is observational only",
                "INFERENCE",
                0.70));

        // 仅显式 HTTP trigger 配置时补 HTTP 回调（证据驱动，非默认）。
        if (context.configContains("elasticjob.http")
                || context.configContains("job.http.trigger")
                || context.configContains("quartz.http")) {
            out.add(new RuntimeCallbackEntry(
                    ID,
                    FRAMEWORK,
                    "HTTP",
                    "POST",
                    "/job/trigger",
                    "elastic-job-http-trigger",
                    List.of("body:jobName"),
                    List.of("framework:" + FRAMEWORK, "callbackKind:http-trigger"),
                    "executor-adapter:" + ID + ":http-trigger",
                    "HTTP job trigger config signal present; route is heuristic INFERENCE",
                    "INFERENCE",
                    0.68));
        }
        return List.copyOf(out);
    }

    @Override
    public Set<String> highValueRouteSignals() {
        return Set.of("/job/trigger");
    }

    @Override
    public Set<String> highValueClassSignals() {
        return Set.of("elasticjob", "elastic-job", "ddframe.job");
    }

    private static boolean hasJobAnnotation(ExecutorEntryContext context) {
        for (ClassMetadata metadata : context.classMetadata()) {
            if (metadata == null || !metadata.annotationMetadataValid()) {
                continue;
            }
            for (ClassMetadata.AnnotationMetadata ann : metadata.annotations()) {
                if (isJobAnn(ann)) {
                    return true;
                }
            }
            for (ClassMetadata.MethodMetadata method : metadata.methods()) {
                for (ClassMetadata.AnnotationMetadata ann : method.annotations()) {
                    if (isJobAnn(ann)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static boolean isJobAnn(ClassMetadata.AnnotationMetadata ann) {
        if (ann == null || ann.typeName() == null) {
            return false;
        }
        String lower = ann.typeName().toLowerCase(Locale.ROOT);
        return lower.endsWith("elasticjobconfiguration")
                || lower.endsWith(".elasticjob")
                || lower.contains("elasticjob");
    }
}

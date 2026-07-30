package com.aq.jvmsentinel.analysis.executor;

import com.aq.jvmsentinel.analysis.ClassMetadata;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ElasticJob / 类 Quartz HTTP 触发适配器。
 *
 * <p>默认仅产出可观测 {@code JOB} protocol（非 HTTP 探针目标），避免把
 * {@code @Scheduled}/纯 ZK 调度硬造成 MVC 入口。仅当配置或注解映射出现
 * 明确 HTTP 触发路径证据时，才写入 EntryCatalog 的 HTTP 回调。
 */
public final class ElasticJobHttpEntryAdapter implements ExecutorEntryAdapter {
    public static final String ID = "elastic-job-http";
    public static final String FRAMEWORK = "elastic-job";

    private static final Pattern HTTP_PATH_PROP = Pattern.compile(
            "(?i)(?:elastic[-.]?job|quartz)\\.(?:http\\.)?(?:trigger[-.]?)?(?:path|url|uri|endpoint)\\s*[=:]\\s*(/\\S{1,128})");
    private static final Pattern HTTP_TRIGGER_FLAG = Pattern.compile(
            "(?i)(?:elastic[-.]?job|quartz)\\.http(?:\\.trigger)?\\s*[=:]\\s*(true|1|yes|enabled|/\\S{1,128})");

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

        ExecutorSurfaceConfig.Surface surface = ExecutorSurfaceConfig.parse(context.configurationLines());
        List<HttpTriggerEvidence> triggers = httpTriggerEvidence(context);
        for (HttpTriggerEvidence trigger : triggers) {
            List<String> pre = new ArrayList<>();
            pre.add("framework:" + FRAMEWORK);
            pre.add("callbackKind:http-trigger");
            pre.add("httpEvidence:" + trigger.kind());
            if (surface.serverPort() > 0) {
                pre = new ArrayList<>(ExecutorSurfaceConfig.withListenPort(pre, surface.serverPort()));
            }
            if (!surface.servletContextPath().isEmpty()) {
                pre = new ArrayList<>(ExecutorSurfaceConfig.withContextPath(
                        pre, surface.servletContextPath()));
            }
            out.add(new RuntimeCallbackEntry(
                    ID,
                    FRAMEWORK,
                    "HTTP",
                    trigger.method(),
                    trigger.path(),
                    trigger.declaringSymbol(),
                    List.of("body:jobName"),
                    List.copyOf(pre),
                    "executor-adapter:" + ID + ":http:" + trigger.path(),
                    "HTTP job trigger evidence=" + trigger.kind()
                            + "; path from " + trigger.source()
                            + "; runtime reachability not proven",
                    trigger.provenance(),
                    trigger.confidence()));
        }
        return List.copyOf(out);
    }

    @Override
    public Set<String> highValueRouteSignals() {
        return Set.of("/job/trigger", "/api/job", "/elasticjob");
    }

    @Override
    public Set<String> highValueClassSignals() {
        return Set.of("elasticjob", "elastic-job", "ddframe.job");
    }

    private static List<HttpTriggerEvidence> httpTriggerEvidence(ExecutorEntryContext context) {
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        List<HttpTriggerEvidence> out = new ArrayList<>();

        for (String line : context.configurationLines()) {
            if (line == null || line.isBlank()) {
                continue;
            }
            Matcher pathMatcher = HTTP_PATH_PROP.matcher(line);
            if (pathMatcher.find()) {
                String path = ExecutorSurfaceConfig.normalizePath(pathMatcher.group(1));
                if (!path.isEmpty() && seen.add("cfg:" + path)) {
                    out.add(new HttpTriggerEvidence(
                            "POST", path, "elastic-job-http-trigger",
                            "config-path", "config:" + pathMatcher.group(0).trim(),
                            "INFERENCE", 0.78));
                }
                continue;
            }
            Matcher flag = HTTP_TRIGGER_FLAG.matcher(line);
            if (flag.find()) {
                String value = flag.group(1).trim();
                if (value.startsWith("/")) {
                    String path = ExecutorSurfaceConfig.normalizePath(value);
                    if (!path.isEmpty() && seen.add("cfg:" + path)) {
                        out.add(new HttpTriggerEvidence(
                                "POST", path, "elastic-job-http-trigger",
                                "config-flag-path", "config:" + flag.group(0).trim(),
                                "INFERENCE", 0.76));
                    }
                }
                // 仅 boolean 开关、无 path —— 不硬造默认 /job/trigger
            }
        }

        // 注解映射：带 ElasticJob 注解/实现的类上的 RequestMapping/GetMapping/PostMapping
        for (ClassMetadata metadata : context.classMetadata()) {
            if (metadata == null || !metadata.annotationMetadataValid()) {
                continue;
            }
            if (!isElasticJobRelated(metadata)) {
                continue;
            }
            for (ClassMetadata.MethodMetadata method : metadata.methods()) {
                String mapping = mappingPath(method.annotations());
                if (mapping == null || mapping.isBlank()) {
                    continue;
                }
                String path = ExecutorSurfaceConfig.normalizePath(mapping);
                if (path.isEmpty() || !seen.add("ann:" + metadata.className() + ":" + path)) {
                    continue;
                }
                String httpMethod = mappingMethod(method.annotations());
                out.add(new HttpTriggerEvidence(
                        httpMethod,
                        path,
                        metadata.className() + "#" + method.name(),
                        "annotation-mapping",
                        "classfile-annotation:" + metadata.className() + "#" + method.name(),
                        "FACT",
                        0.90));
            }
        }
        return out;
    }

    private static boolean isElasticJobRelated(ClassMetadata metadata) {
        if (metadata.className() != null) {
            String lower = metadata.className().toLowerCase(Locale.ROOT);
            if (lower.contains("elasticjob") || lower.contains("elastic-job")
                    || lower.contains("ddframe.job")) {
                return true;
            }
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
        if (metadata.classFact() != null) {
            for (String iface : metadata.classFact().interfaces()) {
                if (iface != null && iface.toLowerCase(Locale.ROOT).contains("elasticjob")) {
                    return true;
                }
            }
            String superName = metadata.classFact().superClassName();
            if (superName != null && superName.toLowerCase(Locale.ROOT).contains("elasticjob")) {
                return true;
            }
        }
        return false;
    }

    private static String mappingPath(List<ClassMetadata.AnnotationMetadata> annotations) {
        if (annotations == null) {
            return null;
        }
        for (ClassMetadata.AnnotationMetadata ann : annotations) {
            if (ann == null || ann.typeName() == null) {
                continue;
            }
            String type = ann.typeName();
            String simple = simpleName(type);
            if (!(simple.endsWith("Mapping") || type.contains("RequestMapping")
                    || type.contains("GetMapping") || type.contains("PostMapping")
                    || type.contains("PutMapping") || type.contains("DeleteMapping")
                    || type.contains("PatchMapping"))) {
                continue;
            }
            String path = firstNonBlank(ann.values("value"));
            if (path.isBlank()) {
                path = firstNonBlank(ann.values("path"));
            }
            if (!path.isBlank()) {
                return path;
            }
        }
        return null;
    }

    private static String mappingMethod(List<ClassMetadata.AnnotationMetadata> annotations) {
        if (annotations == null) {
            return "POST";
        }
        for (ClassMetadata.AnnotationMetadata ann : annotations) {
            if (ann == null || ann.typeName() == null) {
                continue;
            }
            String simple = simpleName(ann.typeName()).toLowerCase(Locale.ROOT);
            if (simple.contains("getmapping")) {
                return "GET";
            }
            if (simple.contains("putmapping")) {
                return "PUT";
            }
            if (simple.contains("deletemapping")) {
                return "DELETE";
            }
            if (simple.contains("patchmapping")) {
                return "PATCH";
            }
            if (simple.contains("postmapping") || simple.contains("requestmapping")) {
                String method = firstNonBlank(ann.values("method"));
                if (!method.isBlank()) {
                    String upper = method.toUpperCase(Locale.ROOT);
                    if (upper.contains("GET")) {
                        return "GET";
                    }
                    if (upper.contains("PUT")) {
                        return "PUT";
                    }
                    if (upper.contains("DELETE")) {
                        return "DELETE";
                    }
                }
                return "POST";
            }
        }
        return "POST";
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

    private static String firstNonBlank(List<String> values) {
        if (values == null) {
            return "";
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return "";
    }

    private static String simpleName(String type) {
        if (type == null) {
            return "";
        }
        int slash = Math.max(type.lastIndexOf('.'), type.lastIndexOf('/'));
        return slash < 0 ? type : type.substring(slash + 1);
    }

    private record HttpTriggerEvidence(
            String method,
            String path,
            String declaringSymbol,
            String kind,
            String source,
            String provenance,
            double confidence
    ) {
    }
}

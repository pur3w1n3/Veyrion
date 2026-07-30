package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.domain.hypothesis.HypothesisFamily;
import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.TraceEvent;
import com.aq.jvmsentinel.domain.pathdebug.TraceEventKind;
import com.aq.jvmsentinel.model.PathRun;
import com.aq.jvmsentinel.model.SqlEvent;
import com.aq.jvmsentinel.model.VerificationStatus;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * 仅服务端验证门禁。
 *
 * <p>H3（SQL 数据流）：当恶意片段出现在实际 JDBC/mock SQL 且未参数化时，
 * 可将 {@code DYNAMIC_SUSPECTED → DYNAMIC_CONFIRMED} 升级。
 *
 * <p>H4（危险 sink 效果）：当 PathTrace 观测到与 finding/securityProperty 匹配的
 * {@code EFFECT_TRIGGERED}，且入口命中、证据可引用时，可升 {@code DYNAMIC_CONFIRMED}。
 * <b>观测细、确认严</b>：Agent 出 EFFECT ≠ 自动确认；仅 HTTP 200 / 仅入口 /
 * 仅 FORCED / 仅 {@code FILE_READ} / 仅 {@code DNS_LOOKUP} → 不得升确认。
 * 框架鉴权自用 SpEL（如 Blade {@code AuthAspect#handleAuth}、Spring Method Security
 * 表达式求值）保留观测，但不得单独升确认或生成「SpEL 注入」孤儿绑定。
 *
 * <p>P2 family fail-closed：Guard / State / Typestate 等非数据流 family
 * 上限为 {@code DYNAMIC_SUSPECTED}，直至独立 family 审计落地。模型不能调用此升级。
 */
public final class DynamicConfirmedGate {
    /**
     * 无 securityProperty 时允许确认的强危险 kind。
     * 故意排除 FILE_READ / FILE_DELETE / DNS_LOOKUP / HTTP_CLIENT（弱或过粗）。
     */
    private static final Set<String> STRONG_CONFIRMABLE_KINDS = Set.of(
            "EXPRESSION", "COMMAND", "SQL", "JDBC", "SSRF", "JNDI",
            "DESERIALIZATION", "FILE_WRITE", "FILE", "PROCESS");

    /** 可出现在 effectKindsOf 归一化结果中的全部 kind（含仅观测）。 */
    private static final Set<String> KNOWN_EFFECT_KINDS = Set.of(
            "EXPRESSION", "COMMAND", "SQL", "JDBC", "SSRF", "JNDI",
            "DESERIALIZATION", "CLASS_LOADING", "FILE", "FILE_WRITE", "FILE_READ",
            "FILE_DELETE", "PROCESS", "HTTP_CLIENT", "DNS_LOOKUP");

    /**
     * 鉴权/方法安全框架对注解表达式的自用求值（非用户输入注入）。
     * 匹配 callerRef / summary「via …」/ subjectRef。
     */
    private static final String[] FRAMEWORK_AUTH_EXPRESSION_MARKERS = {
            "authaspect",
            "methodsecurityinterceptor",
            "prepostadvice",
            "preauthorizeauthorizationmanager",
            "postauthorizeauthorizationmanager",
            "methodsecurityexpressionhandler",
            "methodsecurityexpressionroot",
            "securityexpressionroot",
            "org.springframework.security.access.expression",
            "org.springframework.security.authorization.method",
            "org.springblade.core.secure.aspect",
            "org.springblade.core.secure.utils"
    };

    private DynamicConfirmedGate() { }

    /**
     * SQL 数据流 H3 路径（默认）。等价于
     * {@link #evaluate(PathRun, String, HypothesisFamily)} 且 {@link HypothesisFamily#DATAFLOW}.
     */
    public static VerificationStatus evaluate(PathRun run, String probeMarker) {
        return evaluate(run, probeMarker, HypothesisFamily.DATAFLOW);
    }

    /**
     * 按 family 评估。非 {@link HypothesisFamily#DATAFLOW} family 永不返回
     * {@link VerificationStatus#DYNAMIC_CONFIRMED}（P2 脚手架 / 未审计）。
     */
    public static VerificationStatus evaluate(PathRun run, String probeMarker,
                                              HypothesisFamily family) {
        Objects.requireNonNull(run, "run");
        HypothesisFamily resolved = family == null ? HypothesisFamily.UNKNOWN : family;
        if (!allowsDynamicConfirmed(resolved)) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        // H3 要求同 PathRun 语句证据 + 可重放 evidence refs（P0-06）。
        if (run.sqlEvents().isEmpty()) return VerificationStatus.DYNAMIC_SUSPECTED;
        if (run.evidenceRefs() == null || run.evidenceRefs().isEmpty()) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        if (Boolean.FALSE.equals(run.entryHit())) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        String marker = probeMarker == null ? "" : probeMarker.trim();
        if (marker.isBlank()) return VerificationStatus.DYNAMIC_SUSPECTED;
        String needle = marker.toLowerCase(Locale.ROOT);
        boolean hit = false;
        boolean parameterizedBlock = false;
        for (SqlEvent event : run.sqlEvents()) {
            // 协议 listen/meta 永不能满足 H3；仅语句文本计数。
            if (!isStatementEvidence(event)) continue;
            // Fail-closed：仅凭 MOCK 元数据标志 / maliciousFragmentPresent 不能升级。
            // H3 要求探针 marker 出现在实际语句 SQL 文本中。
            String sql = event.sqlText() == null ? "" : event.sqlText().toLowerCase(Locale.ROOT);
            if (!sql.contains(needle)) continue;
            hit = true;
            if (event.parameterized()) parameterizedBlock = true;
        }
        if (!hit) return VerificationStatus.DYNAMIC_SUSPECTED;
        if (parameterizedBlock) return VerificationStatus.DYNAMIC_SUSPECTED;
        return VerificationStatus.DYNAMIC_CONFIRMED;
    }

    /**
     * H4：危险 sink 效果确认。FORCED/COVERAGE 仅作路径手段；必须观测到匹配的
     * EFFECT_TRIGGERED，不能仅凭 2xx / ENTRY_HIT / INSTRUMENTATION_REACHABILITY。
     *
     * @param securityProperty finding 的 securityProperty（如 EXPRESSION、DESERIALIZATION）
     */
    public static VerificationStatus evaluateEffect(
            PathRun run, PathTrace trace, String securityProperty) {
        Objects.requireNonNull(run, "run");
        if (run.evidenceRefs() == null || run.evidenceRefs().isEmpty()) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        if (Boolean.FALSE.equals(run.entryHit())) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        // 无 HTTP 入口命中时，仍允许 entryHit=null 但 trace 含 ENTRY_HIT+EFFECT 的窗口。
        if (!Boolean.TRUE.equals(run.entryHit()) && !traceHasEntry(trace)) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        // 确认用「可确认 kind」：框架鉴权自用 SpEL 等噪声从确认面剔除，观测仍见 effectKindsOf。
        Set<String> observed = confirmableEffectKinds(trace);
        if (observed.isEmpty()) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        String property = securityProperty == null ? "" : securityProperty.trim().toUpperCase(Locale.ROOT);
        if (property.isBlank()) {
            // 无 property：仅强危险 effect 可确认 PathRun；FILE_READ/DNS 不得升。
            for (String kind : observed) {
                if (STRONG_CONFIRMABLE_KINDS.contains(kind)) {
                    return VerificationStatus.DYNAMIC_CONFIRMED;
                }
            }
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        if (matchesProperty(property, observed)) {
            return VerificationStatus.DYNAMIC_CONFIRMED;
        }
        return VerificationStatus.DYNAMIC_SUSPECTED;
    }

    public static PathRun apply(PathRun run, String probeMarker) {
        return apply(run, probeMarker, HypothesisFamily.DATAFLOW);
    }

    public static PathRun apply(PathRun run, String probeMarker, HypothesisFamily family) {
        VerificationStatus status = evaluate(run, probeMarker, family);
        if (status != VerificationStatus.DYNAMIC_CONFIRMED) return run;
        return withStatus(run, status);
    }

    public static PathRun applyEffect(PathRun run, PathTrace trace, String securityProperty) {
        VerificationStatus status = evaluateEffect(run, trace, securityProperty);
        if (status != VerificationStatus.DYNAMIC_CONFIRMED) return run;
        if (VerificationStatus.DYNAMIC_CONFIRMED.name().equals(run.verificationStatus())) {
            return run;
        }
        return withStatus(run, status);
    }

    /**
     * 为 hypothesis family 钳制提议状态。非 SQL 数据流 family 不能超过
     * {@link VerificationStatus#DYNAMIC_SUSPECTED}；{@code VERIFIED} 全局关闭。
     *
     * <p>说明：H4 effect 确认走 {@link #evaluateEffect}，不经 family cap
     *（效果观测独立于 hypothesis family 脚手架）。
     */
    public static VerificationStatus capForFamily(VerificationStatus proposed,
                                                  HypothesisFamily family) {
        VerificationStatus status = proposed == null
                ? VerificationStatus.DYNAMIC_SUSPECTED : proposed;
        if (status == VerificationStatus.VERIFIED) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        if (status == VerificationStatus.DYNAMIC_CONFIRMED
                && !allowsDynamicConfirmed(family == null ? HypothesisFamily.UNKNOWN : family)) {
            return VerificationStatus.DYNAMIC_SUSPECTED;
        }
        return status;
    }

    /**
     * 在独立 Guard/State/Typestate（及其他非 SQL）family 审计完成前，
     * 仅 SQL 数据流 H3 路径经 family 门可达 {@code DYNAMIC_CONFIRMED}。
     * H4 effect 确认不经过本方法。
     */
    public static boolean allowsDynamicConfirmed(HypothesisFamily family) {
        return family == HypothesisFamily.DATAFLOW;
    }

    public static Set<String> effectKindsOf(PathTrace trace) {
        LinkedHashSet<String> kinds = new LinkedHashSet<>();
        if (trace == null) return Set.of();
        if (trace.effectRefs() != null) {
            for (String ref : trace.effectRefs()) {
                String kind = normalizeEffectToken(ref);
                if (!kind.isBlank()) kinds.add(kind);
            }
        }
        if (trace.events() != null) {
            for (TraceEvent event : trace.events()) {
                if (event == null || event.kind() != TraceEventKind.EFFECT_TRIGGERED) continue;
                String fromDetail = normalizeEffectToken(event.detailCode());
                if (!fromDetail.isBlank()) kinds.add(fromDetail);
                String fromSummary = normalizeEffectToken(event.summary());
                if (!fromSummary.isBlank()) kinds.add(fromSummary);
                String fromSubject = normalizeEffectToken(event.subjectRef());
                if (!fromSubject.isBlank() && KNOWN_EFFECT_KINDS.contains(fromSubject)) {
                    kinds.add(fromSubject);
                }
            }
        }
        return Set.copyOf(kinds);
    }

    /**
     * H4 确认面 kind：在 {@link #effectKindsOf} 基础上剔除不可单独确认的噪声。
     * 当前：仅框架鉴权/方法安全自用 SpEL，或裸 {@code Expression#getValue} 引擎事件
     * → 去掉 EXPRESSION（观测保留，确认与 orphan 绑定不再升）。
     */
    public static Set<String> confirmableEffectKinds(PathTrace trace) {
        Set<String> kinds = new LinkedHashSet<>(effectKindsOf(trace));
        if (kinds.contains("EXPRESSION") && !hasConfirmableExpressionEffect(trace)) {
            kinds.remove("EXPRESSION");
        }
        return Set.copyOf(kinds);
    }

    /**
     * 是否存在可确认为「表达式注入」的 EFFECT：应用侧求值（QLExpress/OGNL/Script 等），
     * 而非 AuthAspect / Method Security 注解 SpEL，也非孤立的 Spring Expression API。
     */
    static boolean hasConfirmableExpressionEffect(PathTrace trace) {
        if (trace == null || trace.events() == null) return false;
        for (TraceEvent event : trace.events()) {
            if (event == null || event.kind() != TraceEventKind.EFFECT_TRIGGERED) continue;
            if (!"EXPRESSION".equals(normalizeEffectToken(event.detailCode()))
                    && !"EXPRESSION".equals(normalizeEffectToken(event.summary()))) {
                continue;
            }
            if (isConfirmableExpressionSite(event)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isConfirmableExpressionSite(TraceEvent event) {
        String caller = expressionCallerOf(event);
        String subject = event.subjectRef() == null ? "" : event.subjectRef().trim();
        if (isFrameworkAuthExpressionSite(caller) || isFrameworkAuthExpressionSite(subject)) {
            return false;
        }
        // 裸 Spring Expression/SpEL API：无应用侧 caller/subject 时只算观测。
        if (isSpringExpressionEngine(subject)
                && (caller.isBlank() || isSpringExpressionEngine(caller))) {
            return false;
        }
        if (caller.isBlank() && subject.isBlank()) {
            return false;
        }
        // 应用侧求值器（QLExpress/OGNL/ScriptEngine/业务类）或带非框架 caller 的 SpEL。
        return true;
    }

    private static String expressionCallerOf(TraceEvent event) {
        if (event == null) return "";
        Object attr = event.attributes() == null ? null : event.attributes().get("callerRef");
        if (attr != null && !attr.toString().isBlank()) {
            return attr.toString().trim();
        }
        String summary = event.summary() == null ? "" : event.summary();
        int via = summary.toLowerCase(Locale.ROOT).lastIndexOf(" via ");
        if (via >= 0 && via + 5 < summary.length()) {
            return summary.substring(via + 5).trim();
        }
        return "";
    }

    static boolean isFrameworkAuthExpressionSite(String symbol) {
        if (symbol == null || symbol.isBlank()) return false;
        String lower = symbol.toLowerCase(Locale.ROOT);
        for (String marker : FRAMEWORK_AUTH_EXPRESSION_MARKERS) {
            if (lower.contains(marker)) return true;
        }
        return false;
    }

    private static boolean isSpringExpressionEngine(String symbol) {
        if (symbol == null || symbol.isBlank()) return false;
        String lower = symbol.toLowerCase(Locale.ROOT);
        return lower.contains("org.springframework.expression.")
                || lower.contains("org.springframework.expression.spel")
                || lower.startsWith("spelExpression#".toLowerCase(Locale.ROOT))
                || lower.equals("expression#getvalue")
                || lower.endsWith(".expression#getvalue")
                || lower.endsWith("spelexpression#getvalue");
    }

    /**
     * securityProperty ↔ 观测 effectKind 严匹配。
     * FILE_READ 不得确认 FILE_WRITE/PATH_TRAVERSAL；DNS_LOOKUP 不得确认 SSRF。
     */
    static boolean matchesProperty(String propertyUpper, Set<String> observedKinds) {
        if (propertyUpper.contains("EXPRESSION") || propertyUpper.contains("TEMPLATE")
                || propertyUpper.contains("SSTI")) {
            return observedKinds.contains("EXPRESSION") || observedKinds.contains("COMMAND");
        }
        if (propertyUpper.contains("DESERIAL") || propertyUpper.contains("REMEMBER_ME")
                || propertyUpper.contains("UNSAFE_DESER")) {
            return observedKinds.contains("DESERIALIZATION");
        }
        if (propertyUpper.contains("SQL") || propertyUpper.contains("JDBC")) {
            return observedKinds.contains("SQL") || observedKinds.contains("JDBC");
        }
        if (propertyUpper.contains("COMMAND") || propertyUpper.contains("RCE")) {
            return observedKinds.contains("COMMAND") || observedKinds.contains("EXPRESSION");
        }
        if (propertyUpper.contains("SSRF")) {
            // 仅 SSRF（URL/HttpClient/RestTemplate/JDBC URL）；DNS_LOOKUP / 裸 HTTP_CLIENT 不够。
            return observedKinds.contains("SSRF") || observedKinds.contains("JDBC");
        }
        if (propertyUpper.contains("HTTP_CLIENT")) {
            return observedKinds.contains("SSRF") || observedKinds.contains("HTTP_CLIENT");
        }
        if (propertyUpper.contains("JNDI")) {
            return observedKinds.contains("JNDI");
        }
        if (propertyUpper.contains("CLASS_LOAD") || propertyUpper.contains("CLASSLOADING")) {
            return observedKinds.contains("CLASS_LOADING");
        }
        if (propertyUpper.contains("FILE_READ") || propertyUpper.equals("READ")) {
            return observedKinds.contains("FILE_READ");
        }
        if (propertyUpper.contains("FILE_WRITE") || propertyUpper.contains("FILE_UPLOAD")) {
            return observedKinds.contains("FILE_WRITE") || observedKinds.contains("FILE");
        }
        if (propertyUpper.contains("FILE_DELETE")) {
            return observedKinds.contains("FILE_DELETE");
        }
        // PATH_TRAVERSAL：写穿越可确认；仅读不足以确认（观测保留 FILE_READ）。
        if (propertyUpper.contains("PATH_TRAVERSAL") || propertyUpper.contains("TRAVERSAL")
                || propertyUpper.equals("PATH")) {
            return observedKinds.contains("FILE_WRITE") || observedKinds.contains("FILE");
        }
        if (propertyUpper.contains("FILE")) {
            // 泛化 FILE：写或遗留 FILE；不含纯读。
            return observedKinds.contains("FILE_WRITE") || observedKinds.contains("FILE");
        }
        // 精确 kind 命中（禁止用 contains 反向把弱信号抬升）
        return observedKinds.contains(propertyUpper);
    }

    private static boolean traceHasEntry(PathTrace trace) {
        if (trace == null || trace.events() == null) return false;
        return trace.events().stream()
                .anyMatch(e -> e != null && e.kind() == TraceEventKind.ENTRY_HIT);
    }

    private static String normalizeEffectToken(String raw) {
        if (raw == null || raw.isBlank()) return "";
        String upper = raw.trim().toUpperCase(Locale.ROOT);
        if (upper.startsWith("EFFECT:")) {
            upper = upper.substring("EFFECT:".length());
        }
        if (upper.contains("EXPRESSION")) return "EXPRESSION";
        if (upper.contains("DESERIAL")) return "DESERIALIZATION";
        if (upper.contains("CLASS_LOAD")) return "CLASS_LOADING";
        if (upper.contains("DNS")) return "DNS_LOOKUP";
        if (upper.equals("SSRF") || upper.endsWith(":SSRF") || upper.contains("SSRF")) {
            return "SSRF";
        }
        if (upper.contains("HTTP_CLIENT")) return "HTTP_CLIENT";
        if (upper.contains("JDBC") || upper.equals("SQL") || upper.contains("SQL_EFFECT")) {
            return upper.contains("JDBC") ? "JDBC" : "SQL";
        }
        if (upper.contains("COMMAND")) return "COMMAND";
        if (upper.contains("JNDI")) return "JNDI";
        if (upper.contains("FILE_WRITE") || upper.equals("FILEWRITE")) return "FILE_WRITE";
        if (upper.contains("FILE_READ") || upper.equals("FILEREAD")) return "FILE_READ";
        if (upper.contains("FILE_DELETE") || upper.equals("FILEDELETE")) return "FILE_DELETE";
        // 遗留糊成 FILE 的写面（Multipart 旧事件）仍归一为 FILE，确认时按写处理。
        if (upper.equals("FILE") || upper.endsWith(":FILE")) return "FILE";
        if (upper.contains("PROCESS")) return "PROCESS";
        int colon = upper.lastIndexOf(':');
        if (colon >= 0 && colon + 1 < upper.length()) {
            return upper.substring(colon + 1).trim();
        }
        return upper;
    }

    private static PathRun withStatus(PathRun run, VerificationStatus status) {
        return new PathRun(
                run.pathRunId(), run.scanId(), run.entrypointRef(), run.track(), run.attemptId(),
                run.experimentPlanId(), run.method(), run.contentType(), run.requestSummary(),
                run.outcomeClass(), run.httpStatus(), run.entryHit(), run.parameterBound(),
                run.sqlEvents(), run.stopReason(), status.name(), run.evidenceRefs(),
                run.identityProvenance(), run.identityPrecondition(), run.branchHitMap());
    }

    private static boolean isStatementEvidence(SqlEvent event) {
        if (event == null) return false;
        String sql = event.sqlText() == null ? "" : event.sqlText().trim();
        if (sql.isBlank()) return false;
        String lower = sql.toLowerCase(Locale.ROOT);
        if (lower.startsWith("port=") || lower.startsWith("sqlclass=")
                || lower.contains("accepted-without-credential")) {
            return false;
        }
        String capture = event.captureMode() == null ? "" : event.captureMode();
        if ("DEPENDENCY_PROTOCOL_MOCK".equals(capture)
                && !(lower.startsWith("select") || lower.startsWith("insert")
                || lower.startsWith("update") || lower.startsWith("delete")
                || lower.startsWith("replace") || lower.contains("?"))) {
            return false;
        }
        return true;
    }
}

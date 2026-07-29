package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.domain.pathdebug.ForcedGuardKind;
import com.aq.jvmsentinel.domain.pathdebug.GuardSurface.DecisionShape;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.Locale;

/**
 * Bounded bytecode heuristic for FORCED GuardSurface candidates.
 * Types implementing Filter / HandlerInterceptor (or Sa-Token equivalents) that call
 * Subject / SecurityContext / StpUtil / getToken become catalog candidates — still gated
 * by the server allowlist at runtime. Never elevates VERIFIED.
 */
public final class GuardSurfaceBytecodeProbe {
    private static final int MAX_CALL_EDGES_SCAN = 64;

    public record ProbeMatch(ForcedGuardKind kind, DecisionShape shape, String simpleName) {
    }

    private GuardSurfaceBytecodeProbe() {
    }

    /** Cheap name gate before reading class bytes. */
    public static boolean looksProbeWorthy(String typeName) {
        if (typeName == null || typeName.isBlank()) {
            return false;
        }
        String simple = simpleName(typeName).toLowerCase(Locale.ROOT);
        String lower = typeName.toLowerCase(Locale.ROOT);
        if (simple.contains("xss") || simple.contains("sqlfilter") || simple.contains("sanitiz")
                || simple.contains("csrf") || simple.contains("characterencoding")
                || simple.contains("corsfilter") || simple.equals("onceperrequestfilter")
                || simple.equals("abstractshirofilter") || simple.equals("genericfilterbean")) {
            return false;
        }
        return simple.endsWith("filter")
                || simple.endsWith("interceptor")
                || lower.contains(".filter.")
                || lower.contains(".interceptor.")
                || lower.contains("satoken")
                || lower.contains("sa-token");
    }

    public static ProbeMatch classify(byte[] classBytes, String typeName) {
        if (classBytes == null || classBytes.length < 16 || typeName == null || typeName.isBlank()) {
            return null;
        }
        String binary = typeName.replace('/', '.');
        String lower = binary.toLowerCase(Locale.ROOT);
        String simple = simpleName(binary).toLowerCase(Locale.ROOT);
        ClassMetadata metadata = ClassFileMetadataParser.parse(classBytes, binary);
        if (!metadata.annotationMetadataValid() || metadata.classFact() == null) {
            return null;
        }
        if (!isFilterOrInterceptorShape(metadata, simple, lower)) {
            return null;
        }
        if (!callsAuthApi(metadata)) {
            return null;
        }
        DecisionShape shape = shapeFor(metadata, simple, lower);
        return new ProbeMatch(ForcedGuardKind.AUTH, shape, simpleName(binary));
    }

    private static boolean isFilterOrInterceptorShape(ClassMetadata metadata, String simple, String lower) {
        BytecodeFactIndex.ClassFact fact = metadata.classFact();
        if (fact != null) {
            if (isFilterTypeName(fact.superClassName()) || isInterceptorTypeName(fact.superClassName())) {
                return true;
            }
            for (String iface : fact.interfaces()) {
                if (isFilterTypeName(iface) || isInterceptorTypeName(iface)) {
                    return true;
                }
            }
        }
        boolean hasDoFilter = false;
        boolean hasPreHandle = false;
        for (ClassMetadata.MethodMetadata method : metadata.methods()) {
            if ("doFilter".equals(method.name()) || "doFilterInternal".equals(method.name())) {
                hasDoFilter = true;
            }
            if ("preHandle".equals(method.name())) {
                hasPreHandle = true;
            }
        }
        if (hasPreHandle && (simple.endsWith("interceptor") || lower.contains("interceptor"))) {
            return true;
        }
        if (hasDoFilter && (simple.endsWith("filter") || lower.contains(".filter."))) {
            return true;
        }
        return simple.equals("sainterceptor") || simple.equals("saservletfilter")
                || simple.contains("satokenfilter");
    }

    private static boolean callsAuthApi(ClassMetadata metadata) {
        int scanned = 0;
        for (BytecodeFactIndex.CallEdge edge : metadata.callEdges()) {
            if (scanned++ >= MAX_CALL_EDGES_SCAN) {
                break;
            }
            if (edge == null) {
                continue;
            }
            String owner = edge.targetOwner() == null ? ""
                    : edge.targetOwner().toLowerCase(Locale.ROOT).replace('.', '/');
            String name = edge.targetName() == null ? "" : edge.targetName().toLowerCase(Locale.ROOT);
            if (owner.contains("org/apache/shiro/subject")
                    || owner.contains("org/apache/shiro/securityutils")
                    || owner.contains("springframework/security/core/context/securitycontext")
                    || owner.contains("springframework/security/core/context/securitycontextholder")
                    || owner.contains("cn/dev33/satoken")
                    || owner.endsWith("/stputil")
                    || owner.contains("/stplogic")
                    || owner.contains("/samanager")) {
                return true;
            }
            if (name.equals("getsubject") || name.equals("getauthentication")
                    || name.equals("getcontext") || name.equals("checklogin")
                    || name.equals("islogin") || name.equals("gettokenvalue")
                    || name.equals("gettoken") || name.equals("checkpermission")
                    || name.equals("hasrole") || name.equals("isauthenticated")
                    || name.equals("getprincipal")) {
                return true;
            }
        }
        for (BytecodeFactIndex.MemberAccessFact access : metadata.memberAccessFacts()) {
            if (access == null) {
                continue;
            }
            String owner = access.targetOwner() == null ? ""
                    : access.targetOwner().toLowerCase(Locale.ROOT).replace('.', '/');
            String name = access.targetName() == null ? "" : access.targetName().toLowerCase(Locale.ROOT);
            if (owner.contains("satoken") || owner.contains("stputil")
                    || owner.contains("securitycontext") || owner.contains("shiro")
                    || (name.contains("token") && (name.startsWith("get") || name.startsWith("check")))) {
                return true;
            }
        }
        return false;
    }

    private static DecisionShape shapeFor(ClassMetadata metadata, String simple, String lower) {
        if (simple.endsWith("interceptor") || lower.contains("interceptor")) {
            return DecisionShape.INTERCEPTOR;
        }
        for (ClassMetadata.MethodMetadata method : metadata.methods()) {
            if ("isAccessAllowed".equals(method.name())) {
                return DecisionShape.ACCESS_CONTROL;
            }
        }
        if (simple.contains("accesscontrol") || simple.equals("loginfilter") || simple.equals("userfilter")) {
            return DecisionShape.ACCESS_CONTROL;
        }
        return DecisionShape.FILTER_CHAIN;
    }

    private static boolean isFilterTypeName(String type) {
        if (type == null || type.isBlank()) {
            return false;
        }
        String n = type.replace('.', '/').toLowerCase(Locale.ROOT);
        return n.equals("javax/servlet/filter")
                || n.equals("jakarta/servlet/filter")
                || n.endsWith("/onceperrequestfilter")
                || n.endsWith("/genericfilterbean")
                || n.contains("saservletfilter");
    }

    private static boolean isInterceptorTypeName(String type) {
        if (type == null || type.isBlank()) {
            return false;
        }
        String n = type.replace('.', '/').toLowerCase(Locale.ROOT);
        return n.contains("handlerinterceptor")
                || n.endsWith("/sainterceptor")
                || n.contains("handlerinterceptoradapter");
    }

    private static String simpleName(String binary) {
        int dot = binary.lastIndexOf('.');
        return dot >= 0 && dot + 1 < binary.length() ? binary.substring(dot + 1) : binary;
    }
}

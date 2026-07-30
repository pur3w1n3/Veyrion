package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.domain.pathdebug.PathTrace;
import com.aq.jvmsentinel.domain.pathdebug.RuntimePostureKind;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.model.PathRun;

import java.util.Locale;

/**
 * 人话权限需求：动态确认 finding 时标注「需要何种身份/权限」才能触发已观测利用效果。
 *
 * <p>不表示生产环境已实测；仅根据本轮 PathRun track / posture / cookie 材料投影。
 */
public final class RequiredPrivilege {
    public static final String ANONYMOUS = "UNAUTHENTICATED";
    public static final String COOKIE_ONLY = "COOKIE_ONLY";
    public static final String LOW_PRIVILEGE_USER = "LOW_PRIVILEGE_USER";
    public static final String ADMIN = "ADMIN";
    public static final String REGISTRATION_REQUIRED = "REGISTRATION_REQUIRED";
    public static final String INSTRUMENTED_ADMIN = "INSTRUMENTED_ADMIN_EQUIVALENT";
    public static final String UNKNOWN = "UNKNOWN";

    private RequiredPrivilege() {
    }

    public static String codeFor(PathRun run, PathTrace trace, boolean cookieChannel) {
        if (run == null) {
            return UNKNOWN;
        }
        IdentityTrack track = run.track();
        RuntimePostureKind posture = postureOf(run, trace);
        if (cookieChannel && (track == IdentityTrack.UNAUTH || track == IdentityTrack.BYPASS_CANDIDATE)) {
            return COOKIE_ONLY;
        }
        if (track == IdentityTrack.UNAUTH && posture == RuntimePostureKind.UNAUTH) {
            return ANONYMOUS;
        }
        if (track == IdentityTrack.USER) {
            return LOW_PRIVILEGE_USER;
        }
        if (posture == RuntimePostureKind.FORCED_REACHABILITY) {
            return INSTRUMENTED_ADMIN;
        }
        if (track == IdentityTrack.ADMIN || posture == RuntimePostureKind.COVERAGE_POSTURE) {
            return ADMIN;
        }
        if (track == IdentityTrack.BYPASS_CANDIDATE) {
            return ANONYMOUS;
        }
        String precondition = run.identityPrecondition() == null ? "" : run.identityPrecondition();
        if (precondition.toLowerCase(Locale.ROOT).contains("register")) {
            return REGISTRATION_REQUIRED;
        }
        return UNKNOWN;
    }

    public static String humanLabel(String code, boolean zh) {
        String normalized = code == null || code.isBlank() ? UNKNOWN : code.trim();
        return switch (normalized) {
            case ANONYMOUS -> zh ? "无需登录（匿名可达）" : "No login required (anonymous)";
            case COOKIE_ONLY -> zh
                    ? "无需登录，持 rememberMe/会话 cookie 即可"
                    : "No login required; rememberMe/session cookie sufficient";
            case LOW_PRIVILEGE_USER -> zh ? "需要已登录低权用户" : "Requires logged-in low-privilege user";
            case ADMIN -> zh ? "需要管理员或等价已鉴权身份" : "Requires admin or equivalent authenticated identity";
            case REGISTRATION_REQUIRED -> zh ? "需先注册/开通账号" : "Requires prior registration";
            case INSTRUMENTED_ADMIN -> zh
                    ? "本轮经强达/扫描身份进入业务；利用需等价管理员或可绕过鉴权的身份"
                    : "Observed via forced/scan identity; exploit needs admin-equivalent or bypassable auth";
            default -> zh ? "权限需求未知（证据不足）" : "Required privilege unknown (insufficient evidence)";
        };
    }

    private static RuntimePostureKind postureOf(PathRun run, PathTrace trace) {
        if (trace != null && trace.posture() != null && trace.posture().postureKind() != null) {
            return trace.posture().postureKind();
        }
        String plan = run.experimentPlanId() == null ? "" : run.experimentPlanId().toLowerCase(Locale.ROOT);
        if (plan.contains("forced")) {
            return RuntimePostureKind.FORCED_REACHABILITY;
        }
        if (plan.contains("coverage")) {
            return RuntimePostureKind.COVERAGE_POSTURE;
        }
        return RuntimePostureKind.UNAUTH;
    }
}

package com.aq.jvmsentinel.security.auth;

import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** workspace 作用域、默认 deny 的 operator 授权。 */
public final class Authorizer {
    private static final Map<OperatorRole, Set<Permission>> DEFAULT_MATRIX = matrix();
    private final Map<OperatorRole, Set<Permission>> rolePermissions;

    public Authorizer() {
        this(DEFAULT_MATRIX);
    }

    public Authorizer(Map<OperatorRole, Set<Permission>> rolePermissions) {
        Objects.requireNonNull(rolePermissions, "rolePermissions");
        EnumMap<OperatorRole, Set<Permission>> copy = new EnumMap<>(OperatorRole.class);
        rolePermissions.forEach((role, permissions) ->
                copy.put(Objects.requireNonNull(role, "role"),
                        Set.copyOf(Objects.requireNonNull(permissions, "permissions"))));
        this.rolePermissions = Map.copyOf(copy);
    }

    public Decision authorize(AuthContext context, String workspaceId, Permission permission) {
        if (context == null || permission == null || workspaceId == null) {
            return Decision.deny("MISSING_AUTHORIZATION_INPUT");
        }
        if (!context.authenticated()) return Decision.deny("UNAUTHENTICATED");
        if (!context.workspaceId().equals(workspaceId)) return Decision.deny("WORKSPACE_SCOPE_MISMATCH");
        boolean granted = context.roles().stream()
                .map(rolePermissions::get)
                .filter(Objects::nonNull)
                .anyMatch(permissions -> permissions.contains(permission));
        return granted ? Decision.allow() : Decision.deny("PERMISSION_DENIED");
    }

    /**
     * 无类型 credential 入口的边界 helper。WorkerCredential 及所有其他
     * 非 operator 类型在 role 评估前即 deny。
     */
    public Decision authorizeCredential(Object candidate, String workspaceId, Permission permission) {
        if (!(candidate instanceof AuthContext context)) {
            return Decision.deny("WRONG_PRINCIPAL_TYPE");
        }
        return authorize(context, workspaceId, permission);
    }

    public Set<Permission> permissionsFor(OperatorRole role) {
        return rolePermissions.getOrDefault(role, Set.of());
    }

    private static Map<OperatorRole, Set<Permission>> matrix() {
        EnumMap<OperatorRole, Set<Permission>> result = new EnumMap<>(OperatorRole.class);
        result.put(OperatorRole.VIEWER, EnumSet.of(Permission.READ_SECURITY_CONFIGURATION));
        result.put(OperatorRole.ANALYST, EnumSet.of(
                Permission.READ_SECURITY_CONFIGURATION, Permission.RUN_AI_JOBS,
                Permission.RUN_SCANS, Permission.READ_AUDIT));
        result.put(OperatorRole.OPERATOR, EnumSet.of(
                Permission.READ_SECURITY_CONFIGURATION, Permission.MANAGE_PROVIDERS,
                Permission.MANAGE_MODELS, Permission.ASSIGN_AGENT_ROLES,
                Permission.ROTATE_PROVIDER_SECRETS, Permission.RUN_AI_JOBS,
                Permission.MANAGE_PROJECTS, Permission.RUN_SCANS, Permission.READ_AUDIT));
        result.put(OperatorRole.ADMINISTRATOR, EnumSet.allOf(Permission.class));
        return Map.copyOf(result);
    }

    public record Decision(boolean allowed, String denialCode) {
        public Decision {
            if (allowed == (denialCode != null)) {
                throw new IllegalArgumentException("decision must be either allow or deny");
            }
        }

        public static Decision allow() { return new Decision(true, null); }
        public static Decision deny(String code) {
            Objects.requireNonNull(code, "code");
            return new Decision(false, code);
        }
    }
}

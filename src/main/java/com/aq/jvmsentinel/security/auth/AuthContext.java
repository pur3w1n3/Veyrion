package com.aq.jvmsentinel.security.auth;

import java.util.Objects;
import java.util.Set;

/** 精确绑定单一 workspace 的已认证 human/operator 上下文。 */
public final class AuthContext {
    private final String operatorId;
    private final String workspaceId;
    private final Set<OperatorRole> roles;
    private final boolean authenticated;

    private AuthContext(String operatorId, String workspaceId, Set<OperatorRole> roles,
                        boolean authenticated) {
        this.operatorId = id(operatorId, "operatorId");
        this.workspaceId = id(workspaceId, "workspaceId");
        this.roles = Set.copyOf(Objects.requireNonNull(roles, "roles"));
        this.authenticated = authenticated;
        if (authenticated && this.roles.isEmpty()) {
            throw new IllegalArgumentException("authenticated operator must have at least one role");
        }
        if (!authenticated && !this.roles.isEmpty()) {
            throw new IllegalArgumentException("unauthenticated context cannot carry roles");
        }
    }

    public static AuthContext authenticated(String operatorId, String workspaceId,
                                            Set<OperatorRole> roles) {
        return new AuthContext(operatorId, workspaceId, roles, true);
    }

    public static AuthContext unauthenticated(String workspaceId) {
        return new AuthContext("anonymous", workspaceId, Set.of(), false);
    }

    public String operatorId() { return operatorId; }
    public String workspaceId() { return workspaceId; }
    public Set<OperatorRole> roles() { return roles; }
    public boolean authenticated() { return authenticated; }

    private static String id(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank() || value.length() > 256
                || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(name + " is invalid");
        }
        return value;
    }
}

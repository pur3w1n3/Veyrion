package com.aq.jvmsentinel.security.auth;

/** human/operator role。这些 role 永不分配给 Worker credential。 */
public enum OperatorRole {
    VIEWER,
    ANALYST,
    OPERATOR,
    ADMINISTRATOR
}
